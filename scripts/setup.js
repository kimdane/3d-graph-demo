'use strict';
const db = require('@arangodb').db;
const graphModule = require('@arangodb/general-graph');

const stixCapecRecords = require('./stix-capec.json').objects;
const enterpriseAttackRecords = require('./enterprise-attack.json').objects;

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
  "memberOf",
  "relationship"
];
const graphName = "vulnsPerScan";
const stixGraphName = "stixCapec";


for (const localName of documentCollections) {
  //const qualifiedName = module.context.collectionName(localName);
  const qualifiedName = localName;
  if (!db._collection(qualifiedName)) {
    db._createDocumentCollection(qualifiedName);
  } else if (module.context.isProduction) {
    console.debug(`collection ${qualifiedName} already exists. Leaving it untouched.`)
  }
}

for (const localName of edgeCollections) {
  const qualifiedName = localName;
  if (!db._collection(qualifiedName)) {
    db._createEdgeCollection(qualifiedName);
  } else if (module.context.isProduction) {
    console.debug(`collection ${qualifiedName} already exists. Leaving it untouched.`)
  }
}

//const users = module.context.collection('users');
//users.ensureIndex({
//  type: 'hash',
//  fields: ['username'],
//  unique: true
//});

if (graphModule._exists(graphName)) {
  console.debug(`Graph ${graphName} already exists. Leaving it untouched.`);
}
else {
  graphModule._create(graphName, [
    graphModule._relation(
      "found_in",
      documentCollections,
      documentCollections
    )
  ]);
}
   
let updated = 0;
let created = 0;
let stixColls = [];
let cveRegex = /[cC][vV][eE]-([12][90]\d\d-\d\d\d\d)/g;
let allRecords = stixCapecRecords.concat(enterpriseAttackRecords);
//for (let r=0;r<stixCapecRecords.length; r++) {
//    let record = stixCapecRecords[r];
for(const record of allRecords) {
    let qualifiedName = record.type;
    record._key = record.id.split("--")[1];
    let coll = db._collection(qualifiedName);
    if (qualifiedName && qualifiedName != null) {
      if (!coll) {
        if (qualifiedName == 'relationship') {
          coll = db._createEdgeCollection(qualifiedName)
        } else {
          coll = db._createDocumentCollection(qualifiedName);
        }
        console.debug(`collection ${qualifiedName} created.`);
      }
      
      if (qualifiedName == 'relationship') {
        record._from = record.source_ref.replace("--","/");
        record._to = record.target_ref.replace("--","/");
        record.label = record.relationship_type;
      } else {
        stixColls.push(qualifiedName);
      }
      
      try {
          if (record.external_references && record.external_references.length) {
            for (const ref of record.external_references) {
              const matches = []
              for (const match of [...ref.description.matchAll(cveRegex)]) {
                matches.push(match[1]);
              }
              const cves = [...new Set(matches)];
              for (var c=0;c<cves.length;c++) {
                var vulnId = "vulnerability/CVE-" + cves[c];
                var vulCol = db._collection("vulnerability");
                try {
                  vulCol.save({_key: "CVE-" + cves[c]});
                  created++;
                } catch {
                  console.debug(`${vulnId} exists`);
                  updated++;
                }
                var relationship = {_from: record.id.replace("--","/"), _to: vulnId};
                var relCol = db._collection("found_in");
                relCol.save(relationship);
              }
            }
          }
          coll.save(record);
          created++;
          console.debug(`Created ${record.id}`);
      } catch {
        try {
          coll.update(record._key, record, {"overwrite": true});
        } catch {
          console.debug(`Error ${record}`);
        }
          updated++;
          console.debug(`Updated ${record.id}`);
      }
    } else {
      console.error(`Had error with ${record.id}`);
    }
}
const stixCollections = [...new Set(stixColls)];


try {
  if (graphModule._exists(stixGraphName)) {
    console.debug(`Graph ${stixGraphName} already exists. Leaving it untouched.`);
  }
  else {
    graphModule._create(stixGraphName, [
      graphModule._relation(
        "relationship",
        stixCollections,
        stixCollections
      ),
      graphModule._relation(
      "found_in",
      documentCollections,
      documentCollections
    )
    ]);
  }
} catch (error) {
  console.error(`Had error with ${error}`);
}

 console.log(`Using ${stixCollections.length} collections and created ${created}, and updated ${updated} of total ${created+updated} records.`);
