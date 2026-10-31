import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { ToolError } from './security.js';
import conflicts from './contract-conflicts.json' with { type: 'json' };
import ledger from './normalization-ledger.json' with { type: 'json' };
import { catalogue } from './catalogue.js';

interface Schema {
  [keyword: string]: unknown;
  $ref?: string;
  type?: string | string[];
  enum?: unknown[];
  format?: string;
  properties?: Record<string, Schema>;
  required?: string[];
  allOf?: Schema[];
  items?: Schema;
  additionalProperties?: Schema | boolean;
  discriminator?: { propertyName: string; mapping: Record<string, string> };
  minimum?: number; maximum?: number;
  minLength?: number; maxLength?: number;
  minItems?: number; maxItems?: number;
  uniqueItems?: boolean;
}
interface Source { components: { schemas: Record<string, Schema> }; paths: Record<string, Record<string, {
  parameters?: { schema: Schema }[];
  requestBody?: { content: Record<string, { schema?: Schema }> };
  responses: Record<string, { content?: Record<string, { schema?: Schema }> }>;
}>> }
type Check = (value: unknown, path: string, inherited: boolean) => string[];
const keywords = new Set(['$ref', 'type', 'enum', 'format', 'properties', 'required', 'allOf', 'items',
  'additionalProperties', 'discriminator', 'minimum', 'maximum', 'minLength', 'maxLength', 'minItems', 'maxItems',
  'uniqueItems', 'description', 'example', 'default', 'deprecated', 'title', 'readOnly', 'writeOnly', 'x-tags']);
const escape = (key: string) => key.replaceAll('~', '~0').replaceAll('/', '~1');

function freeze(value: unknown): void {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
}

// This compiler supports the keywords in the retained contracts, and fails closed on additions.
export function compileContract(source: unknown, version: string) {
  const document = structuredClone(source) as Source;
  freeze(document);
  const compiled = new Map<string, Check>();
  function at(pointer: string): Schema {
    if (!pointer.startsWith('#/')) throw new Error(`Unsupported schema reference: ${pointer}`);
    let value: unknown = document;
    for (const part of pointer.slice(2).split('/')) {
      if (!value || typeof value !== 'object') throw new Error(`Missing schema: ${pointer}`);
      value = (value as Record<string, unknown>)[part.replaceAll('~1', '/').replaceAll('~0', '~')];
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`Missing schema: ${pointer}`);
    return value as Schema;
  }
  function compile(schema: Schema, pointer: string): Check {
    const cached = compiled.get(pointer);
    if (cached) return cached;
    for (const keyword of Object.keys(schema)) {
      if (!keywords.has(keyword)) throw new Error(`Unsupported validation keyword ${keyword} at ${pointer}`);
    }
    const forward: Check = (value, path, inherited) => check(value, path, inherited);
    compiled.set(pointer, forward);
    const reference = schema.$ref ? compile(at(schema.$ref), schema.$ref) : undefined;
    const parents = (schema.allOf ?? []).map((parent, index) => compile(parent, `${pointer}/allOf/${index}`));
    const properties = Object.entries(schema.properties ?? {}).map(([name, child]) =>
      [name, compile(child, `${pointer}/properties/${escape(name)}`)] as const);
    const items = schema.items ? compile(schema.items, `${pointer}/items`) : undefined;
    const additional = typeof schema.additionalProperties === 'object' ? compile(schema.additionalProperties, `${pointer}/additionalProperties`) : undefined;
    const mapping = new Map(Object.entries(schema.discriminator?.mapping ?? {}).map(([tag, ref]) => [tag, compile(at(ref), ref)]));
    const resolution = ledger.resolutions.find(rule => rule.version === version && rule.pointer === pointer);
    const enumValues = resolution ? resolution.positive : schema.enum;
    const check: Check = (value, path, inherited) => {
      // NORM-001: this response field alone documents null as disabled.
      if (value === null && ledger.nullResponses.some(rule => rule.version === version && rule.pointer === pointer)) return [];
      const errors: string[] = [];
      const fail = (message: string) => errors.push(`${path}: ${message} [schema=${pointer}]`);
      if (reference) errors.push(...reference(value, path, inherited));
      for (const parent of parents) errors.push(...parent(value, path, true));
      const object = value !== null && typeof value === 'object' && !Array.isArray(value);
      const matches = (type: string): boolean => {
        switch (type) {
          case 'object': return object;
          case 'array': return Array.isArray(value);
          case 'integer': return typeof value === 'number' && Number.isInteger(value);
          case 'number': return typeof value === 'number' && Number.isFinite(value);
          case 'null': return value === null;
          case 'string': return typeof value === 'string';
          case 'boolean': return typeof value === 'boolean';
          default: throw new Error(`Unsupported schema type: ${type}`);
        }
      };
      if (schema.type && !(Array.isArray(schema.type) ? schema.type : [schema.type]).some(matches)) fail('wrong type');
      if (enumValues && !enumValues.some(member => isDeepStrictEqual(member, value))) fail('outside enum');
      if (typeof value === 'number') {
        if (schema.minimum !== undefined && value < schema.minimum) fail('below minimum');
        if (schema.maximum !== undefined && value > schema.maximum) fail('above maximum');
        if (schema.format === 'int32' && (!Number.isInteger(value) || value < -2147483648 || value > 2147483647)) fail('outside int32');
        if (schema.format === 'int64' && (!Number.isInteger(value) || value < -(2 ** 63) || value >= 2 ** 63)) fail('outside int64');
      }
      if (typeof value === 'string') {
        const length = [...value].length;
        if (schema.minLength !== undefined && length < schema.minLength) fail('too short');
        if (schema.maxLength !== undefined && length > schema.maxLength) fail('too long');
        if (schema.format === 'uuid' && !/^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/i.test(value)) fail('invalid uuid');
        if (['date', 'date-time'].includes(schema.format ?? '') &&
          (!/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))?$/.test(value) ||
            (schema.format === 'date' ? value.length !== 10 : value.length <= 10) || !Number.isFinite(Date.parse(value)))) fail('invalid date');
      }
      if (Array.isArray(value)) {
        if (schema.minItems !== undefined && value.length < schema.minItems) fail('too few items');
        if (schema.maxItems !== undefined && value.length > schema.maxItems) fail('too many items');
        if (schema.uniqueItems && value.some((item, index) => value.slice(0, index).some(other => isDeepStrictEqual(item, other)))) fail('duplicate items');
        if (items) value.forEach((item, index) => errors.push(...items(item, `${path}/${index}`, false)));
      }
      if (object) {
        const record = value as Record<string, unknown>;
        for (const name of schema.required ?? []) if (!Object.hasOwn(record, name)) fail(`missing required ${name}`);
        for (const [name, child] of properties) if (Object.hasOwn(record, name)) errors.push(...child(record[name], `${path}/${escape(name)}`, false));
        for (const name of Object.keys(record)) if (!Object.hasOwn(schema.properties ?? {}, name)) {
          if (schema.additionalProperties === false) fail(`unexpected property ${name}`);
          if (additional) errors.push(...additional(record[name], `${path}/${escape(name)}`, false));
        }
      }
      if (schema.discriminator && !inherited) {
        const tag = object ? (value as Record<string, unknown>)[schema.discriminator.propertyName] : undefined;
        const selected = typeof tag === 'string' ? mapping.get(tag) : undefined;
        if (!selected) fail(`missing or unmapped discriminator ${schema.discriminator.propertyName}`);
        else errors.push(...selected(value, path, false));
      }
      return errors;
    };
    return forward;
  }
  for (const [name, schema] of Object.entries(document.components.schemas)) compile(schema, `#/components/schemas/${escape(name)}`);
  for (const [path, methods] of Object.entries(document.paths)) for (const [method, operation] of Object.entries(methods)) {
    const base = `#/paths/${escape(path)}/${method}`;
    for (const [index, parameter] of (operation.parameters ?? []).entries()) compile(parameter.schema, `${base}/parameters/${index}/schema`);
    for (const [status, response] of Object.entries(operation.responses)) for (const [media, body] of Object.entries(response.content ?? {})) {
      if (body.schema) compile(body.schema, `${base}/responses/${status}/content/${escape(media)}/schema`);
    }
    for (const [media, body] of Object.entries(operation.requestBody?.content ?? {})) {
      if (body.schema) compile(body.schema, `${base}/requestBody/content/${escape(media)}/schema`);
    }
  }
  return {
    validate(pointer: string, value: unknown): string[] { return compile(at(pointer), pointer)(value, '', false); },
    structuralConflicts(pointer: string) {
      const reachable = new Set<string>();
      function visit(schema: Schema, location: string): void {
        if (reachable.has(location)) return;
        reachable.add(location);
        if (schema.$ref) visit(at(schema.$ref), schema.$ref);
        for (const ref of Object.values(schema.discriminator?.mapping ?? {})) visit(at(ref), ref);
        for (const [name, child] of Object.entries(schema.properties ?? {})) visit(child, `${location}/properties/${escape(name)}`);
        for (const [index, child] of (schema.allOf ?? []).entries()) visit(child, `${location}/allOf/${index}`);
        if (schema.items) visit(schema.items, `${location}/items`);
        if (typeof schema.additionalProperties === 'object') visit(schema.additionalProperties, `${location}/additionalProperties`);
      }
      visit(at(pointer), pointer);
      return conflicts.rows.filter(row => row.version === version && row.status === 'blocked' &&
        row.kind !== 'description_vs_null_schema' && reachable.has(row.pointer));
    },
  };
}

const validators = new Map<string, ReturnType<typeof compileContract>>();
const hashes: Record<string, string> = {
  '10.6.109': '2356b910f76c175db9a22ce18070c2c40af02d9843ca67628410a5afbfc5086c',
  '11.0.97': '0828aa9f017cce92cd035429c7e19c933d0b3387c561aac17c468b4c2ca8be66',
};
export function contractValidator(version: string) {
  if (!Object.hasOwn(hashes, version)) throw new ToolError('UNVERIFIED_API_VERSION', 'No validation contract for this version.');
  let validator = validators.get(version);
  if (!validator) {
    const bytes = readFileSync(new URL(`../evidence/sources/network-${version}-openapi.json`, import.meta.url));
    if (createHash('sha256').update(bytes).digest('hex') !== hashes[version]) throw new Error('Source contract hash mismatch');
    validator = compileContract(JSON.parse(bytes.toString()), version);
    validators.set(version, validator);
  }
  return validator;
}

export function contractConflicts(version: string, family?: string) {
  return conflicts.rows.filter(row => row.version === version &&
    (family === undefined || row.assignments.some(assignment => assignment.family === family)));
}

export function validateResponse(version: string, operationId: string, value: unknown): void {
  const operation = catalogue.find(operation => operation.id === operationId);
  if (!operation) throw new Error(`Unknown operation: ${operationId}`);
  const pointer = `#/paths/${escape(operation.path)}/${operation.method.toLowerCase()}/responses/200/content/application~1json/schema`;
  const validator = contractValidator(version);
  const blocked = validator.structuralConflicts(pointer);
  // CF-007 remains a device-family gate until a version-specific PoE resolution is approved.
  if (version === '11.0.97' && operation.command.startsWith('device ')) {
    const poe = contractConflicts(version, 'device').find(row => row.id === 'CF-007' && row.status === 'blocked');
    if (poe && !blocked.includes(poe)) blocked.push(poe);
  }
  if (blocked.length) throw new ToolError('CONTRACT_CONFLICT', `Response validation blocked by ${blocked.map(row => `${row.id} ${row.pointer}`).join(', ')}.`);
  const errors = validator.validate(pointer, value);
  if (errors.length) throw new ToolError('RESPONSE_INVALID', `Response does not match the selected version contract: ${errors[0]}`);
}
