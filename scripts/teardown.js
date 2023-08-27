'use strict';
const db = require('@arangodb').db;
const graphModule = require('@arangodb/general-graph');


const documentCollections = [
  "securityScan",
  "artifact",
  "vulnerability",
  "dockerImage",
  "patients",
  "users",
  "usergroups",
  "sessions"
];
const edgeCollections = [
  "found_in",
  "hasPerm",
  "memberOf"
];
const graphName = "vulnsPerScan";

for (const localName of documentCollections) {
  //const qualifiedName = module.context.collectionName(localName);
  const qualifiedName = localName;
  if (db._collection(qualifiedName)) {
    db._drop(qualifiedName);
  } else if (module.context.isProduction) {
    console.debug(`collection ${qualifiedName} does not exists. Leaving it untouched.`)
  }
}

for (const localName of edgeCollections) {
  const qualifiedName = localName;
  if (db._collection(qualifiedName)) {
    db._drop(qualifiedName);
  } else if (module.context.isProduction) {
    console.debug(`collection ${qualifiedName} does not exists. Leaving it untouched.`)
  }
}

const users = module.context.collection('users');
users.ensureIndex({
  type: 'hash',
  fields: ['username'],
  unique: true
});

if (!graphModule._exists(graphName)) {
  console.debug(`Graph ${graphName} does not exists. Leaving it untouched.`);
}
else {
  graphModule._drop(graphName);
}