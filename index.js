'use strict';
const util = require('util');
const createRouter = require('@arangodb/foxx/router');
const router = createRouter();

module.context.use(router);

const db = require('@arangodb').db;
const query = require('@arangodb').query;
const errors = require('@arangodb').errors;
const joi = require('joi');
const DOC_NOT_FOUND = errors.ERROR_ARANGO_DOCUMENT_NOT_FOUND.code;

const foxxCollSecurityScan = db._collection('securityScan');
const foxxCollArtifact = db._collection('artifact');
const foxxCollVuln = db._collection('vulnerability');
const foxxCollImage = db._collection('dockerImage');
const foxxCollFoundIn = db._collection('found_in');


router.post('/syft-grype-scan', function (req, res) {
  const data = req.body;
  const meta = foxxCollSecurityScan.save(req.body);
  foxxCollSecurityScan.update(meta, {id: meta._id, name: meta._key}); 
  var image;
  var link;
  if (data.source.type == 'image') {
    data.source.target['distro'] = data.source.distro;
    data.source.target['name'] = data.source.target.tags[0];
    image = Object.assign(data.source.target, foxxCollImage.save(data.source.target)); 
    link = {"_to": meta._id, "_from": image._id};
    Object.assign(link, foxxCollFoundIn.save(link));
  }
  data.matches.forEach(record => { 
    const artifact = Object.assign(record.artifact, foxxCollArtifact.save(record.artifact)); 
    if (data.source.type == 'image') {
      link = {"_to": image._id, "_from": artifact._id};
    } else {
      link = {"_to": meta._id, "_from": artifact._id};
    }
    Object.assign(link, foxxCollFoundIn.save(link));
    
    var vulnRec = {};
    if (record.vulnerability.namespace == 'nvd:cpe') {
      vulnRec = record.vulnerability;
    } else if (record.relatedVulnerabilities[0]) {
      vulnRec = record.relatedVulnerabilities[0]; 
    }
    vulnRec['name'] = record.vulnerability.id;
    vulnRec['_id'] = "vulnerability/" + record.vulnerability.id;
    const vuln = Object.assign(vulnRec, foxxCollVuln.save(vulnRec)); 
    link = {"_to": artifact._id, "_from": vuln._id};
    Object.assign(link, foxxCollFoundIn.save(link));
  });
  res.send(Object.assign(data, meta));
})
.body(joi.object().required(), 'Entry to store in the collection.')
.response(joi.object().required(), 'Entry stored in the collection.')
.summary('Store an entry')
.description('Stores an entry in the "myFoxxCollection" collection.');

router.get("/", function(req, res) {
  const filePath = module.context.fileName("index.html");
  res.sendFile(filePath);
});

router.get("/graph/:id", (req, res) => {
  const startNode = req.pathParams.id
  const depth = 6;
  const result = res.json(query`
	RETURN  { nodes: (
  FOR vertex
  IN 0..${depth} 
  INBOUND ${startNode}
  GRAPH "vulnsPerScan"
    RETURN {_id: vertex._id, id: vertex._id, type: SPLIT(vertex._id, "/")[0], 
      name: vertex.name, severity: vertex.severity, description: vertex.description}
), links: (
  FOR vertex, edge
  IN 1..${depth} 
  INBOUND ${startNode}
  GRAPH "vulnsPerScan"
    RETURN {source: edge._from, target: edge._to, _id: edge._id, id: edge._id}
) }
  `.toArray()[0]);
  if (result) {
    return result;
  } else {
    res.throw(404, 'Object not in graph');
  }
})
.pathParam('id', joi.string().required(), 'The canonical id of the graph node.');

router.get("/bi-graph/:id", (req, res) => {
  const startNode = req.pathParams.id
  const result = res.json(query`
	RETURN  { nodes: (
  FOR vertex
  IN 0..3 
  ANY ${startNode}
  GRAPH "vulnsPerScan"
    RETURN {_id: vertex._id, id: vertex._id, type: SPLIT(vertex._id, "/")[0], 
    name: vertex.name, severity: vertex.severity, description: vertex.description}
), links: (
  FOR vertex, edge
  IN 1..3 
  ANY ${startNode}
  GRAPH "vulnsPerScan"
    RETURN {source: edge._from, target: edge._to, _id: edge._id, id: edge._id}
) }
  `.toArray()[0]);
  if (result) {
    return result;
  } else {
    res.throw(404, 'Object not in graph');
  }
})
.pathParam('id', joi.string().required(), 'The canonical id of the graph node.');


router.get("/stix", function(req, res) {
  const filePath = module.context.fileName("stix.html");
  res.sendFile(filePath);
});
router.get('/stix-startNode', (req, res) => {
  res.json(query`
  FOR doc IN relationship
    SORT RAND() LIMIT 1
  RETURN doc._to`.toArray()[0]);
});
router.get("/stix-graph/:id", (req, res) => {
  const startNode = req.pathParams.id
  const depth = 6;
  const graph = "stixCapec"
  const result = res.json(query`
	RETURN  { nodes: (
  FOR vertex
  IN 0..${depth} 
  INBOUND ${startNode}
  GRAPH ${graph}
    RETURN {_id: vertex._id, id: vertex._id, type: SPLIT(vertex._id, "/")[0], 
      name: vertex.name, severity: vertex.severity, description: vertex.description}
), links: (
  FOR vertex, edge
  IN 1..${depth} 
  INBOUND ${startNode}
  GRAPH ${graph}
    RETURN {source: edge._from, target: edge._to, _id: edge._id, id: edge._id, label: edge.label}
) }
  `.toArray()[0]);
  if (result) {
    return result;
  } else {
    res.throw(404, 'Object not in graph');
  }
})
.pathParam('id', joi.string().required(), 'The canonical id of the graph node.');

router.get("/stix-bigraph/:id", (req, res) => {
  const startNode = req.pathParams.id
  const depth = 2;
  const graph = "stixCapec"
  const result = res.json(query`
	RETURN  { nodes: (
  FOR vertex
  IN 0..${depth} 
  OUTBOUND ${startNode}
  GRAPH ${graph}
    RETURN {_id: vertex._id, id: vertex._id, type: SPLIT(vertex._id, "/")[0], 
      name: vertex.name, severity: vertex.severity, description: vertex.description}
), links: (
  FOR vertex, edge
  IN 1..${depth} 
  OUTBOUND ${startNode}
  GRAPH ${graph}
    RETURN {source: edge._from, target: edge._to, _id: edge._id, id: edge._id, label: edge.label}
) }
  `.toArray()[0]);
  if (result) {
    return result;
  } else {
    res.throw(404, 'Object not in graph');
  }
})
.pathParam('id', joi.string().required(), 'The canonical id of the graph node.');

router.get('/stix-node/:id', (req, res) => {
  const nodeId = req.pathParams.id.replace("--", "/");
  const json = query`
	RETURN DOCUMENT(${nodeId})
  `.toArray()[0];
  const relsTo = query`
	FOR rel IN relationship
  FILTER rel._from == ${nodeId}
  RETURN SUBSTITUTE(rel._to, "/", "--")
  `.toArray();
  const relsFrom = query`
	FOR rel IN relationship
  FILTER rel._to == ${nodeId}
  RETURN SUBSTITUTE(rel._from, "/", "--")
  `.toArray();
  const found_in = query`
	FOR rel IN found_in
  FILTER rel._to == ${nodeId} OR rel._from == ${nodeId}
  RETURN rel._from == ${nodeId} ? SUBSTITUTE(rel._to, "/", "--") : SUBSTITUTE(rel._from, "/", "--")
  `.toArray();
  json['found_in'] = found_in;
  json['relationship_to'] = relsTo;
  json['relationship_from'] = relsFrom;
  //var json = JSON.stringify(node);
  //var formattedJson = json.replace(/(http[^"]*)/g, "<a href='$1'>$1</a>");
  //json.replaceAll(/"\(http[^"]*\)"/g, '"<a href=\"$1\">$1</a>"');
  var page = `<html>
<html><head><script type="text/javascript" src="../js/json-viewer.js"></script>
<link rel="stylesheet" href="../css/json-viewer.css"></head>
<body><div id="json"></div>
<script>
var jsonViewer = new JSONViewer();
document.querySelector("#json").appendChild(jsonViewer.getContainer());
jsonViewer.showJSON(${JSON.stringify(json)});
</script></body></html>`;
  res.type('html');
  res.send(page);
})
.pathParam('id', joi.string().required(), 'The canonical id of the graph node.');

//router.get("/graph/:id", (req, res) => {
//  const startNode = req.pathParams.id
//  
//  let nodes=[
//    {_id: startNode.toString(), id: startNode.toString(), name: startNode.toString()}
//  ];
//  const links = query`
//	FOR node in 1..2 INBOUND ${startNode}
//	GRAPH "vulnsPerScan" LIMIT 10 
//	RETURN { target: ${startNode}, source: node._id, data: node, id: ${startNode}+node._id}
//  `.toArray();
//  if (links.length) {
//    for (let i=0;i<links.length;i++) {
//      links[i].data['id'] = links[i].data._id;
//      links[i].data['type'] = links[i].data._id.split('/')[0];
//      nodes.push(links[i].data);
//    }
//    res.json({nodes: nodes, links: links});
//  } else {
//    res.throw(404, 'Object not in graph');
//  }
//})
//.pathParam('id', joi.string().required(), 'The canonical id of the graph node.');

router.get("/bad-graph/:id", (req, res) => {
  const startNode = req.pathParams.id;
  const nodes = [];
  const links = query`
	FOR node in 0..4 ANY ${startNode}
	GRAPH "vulnsPerScan" 
	RETURN { target: ${startNode}, source: node._id, data: node, id: ${startNode}+node._id}
  `.toArray();
  if (links.length && links[0].data) {
    nodes.push(links.shift().data);
    for (let i=0;i<links.length;i++) {
      links[i].data['id'] = links[i].data._id;
      links[i].data['type'] = links[i].data._id.split('/')[0];
      nodes.push(links[i].data);
    }
    res.json({nodes: nodes, links: links});
  } else {
    res.throw(404, 'Object not in graph');
  }
})
.pathParam('id', joi.string().required(), 'The canonical id of the graph node.');

router.get('/startNode', (req, res) => {
  res.json(query`
  FOR doc IN securityScan
    SORT RAND() LIMIT 1
  RETURN doc.id`.toArray()[0]);
});

router.get('/node/:id', (req, res) => {
  const startNode = req.pathParams.id;
  const json = query`
	RETURN DOCUMENT(${startNode})
  `.toArray()[0];
  var page = `<html>
<html><head><script type="text/javascript" src="../js/json-viewer.js"></script>
<link rel="stylesheet" href="../css/json-viewer.css"></head>
<body><div id="json"></div>
<script>
var jsonViewer = new JSONViewer();
document.querySelector("#json").appendChild(jsonViewer.getContainer());
jsonViewer.showJSON(${JSON.stringify(json)});
</script></body></html>`;
//jsonViewer.showJSON(${util.inspect(json)});
//jsonViewer.showJSON({  "nodes": [    {"id": "byt6i8hiuon3dgd", "name": "kimdane.dummy", "type": "artifact"},    {"id": "byt6iuon3dgd", "name": "platform/kimdane-security", "type": "vault_namespace"},    {"id": "byt6iuongd", "name": "kimdane", "type": "ns"},    {"id": "byiuongd", "name": "kimdane", "type": "project"},    {"id": "byiuongr", "name": "dummy-repo", "type": "repo"},    {"id": "byi8hiugd", "name": "kimdane/dummy", "hash": "jno87t7gtvyik7givu", "tag": "latest", "tag_timestamp": "1635589478", "type": "image"},    {"id": "byuon3dgd", "name": "dummy-deployment", "type": "deploy"},    {"id": "byuon3dgds", "name": "dummy-service", "type": "svc"},    {"id": "byuon3dgdi", "name": "dummy-ingress", "host": "dummy.oneadp.com", "port": 8080, "type": "ing"},    {"id": "byuon3dgdp", "name": "dummy-pod-456gh", "type": "pod"},    {"id": "byuon3dgdc", "name": "dummy-container", "ports": [8080], "type": "container"},    {"id": "k8s-cluster1", "name": "k8s-cluster1", "type": "cluster"},    {"id": "byuon", "name": "k8s-cluster1-456ythgfr", "type": "node"}  ],  "links": [    {"source": "k8s-cluster1", "target": "byuon", "value": 1},    {"source": "byuon", "target": "byt6iuongd", "value": 1},    {"source": "byt6iuongd", "target": "byuon3dgd", "value": 1},    {"source": "byuon3dgd", "target": "byuon3dgds", "value": 1},    {"source": "byuon3dgdi", "target": "byuon3dgds", "value": 1},    {"source": "byuon3dgds", "target": "byuon3dgdp", "value": 1},    {"source": "byuon3dgdp", "target": "byuon3dgdc", "value": 1},    {"source": "byiuongr", "target": "byt6i8hiuon3dgd", "value": 2},    {"source": "byiuongd", "target": "byiuongr", "value": 2},    {"source": "byt6i8hiuon3dgd", "target": "byi8hiugd", "value": 1},    {"source": "byi8hiugd", "target": "byuon3dgdc", "value": 2},    {"source": "byuon3dgdc", "target": "byuon3dgdi", "value": 1},    {"source": "byt6iuon3dgd", "target": "byt6iuongd", "value": 0}  ]}, 10, 10);

  res.type('html');
  res.send(page);
})
.pathParam('id', joi.string().required(), 'The canonical id of the graph node.');

router.get('/sample.json', function (req, res) {
  res.send('{  "nodes": [    {"id": "byt6i8hiuon3dgd", "name": "kimdane.dummy", "type": "artifact"},    {"id": "byt6iuon3dgd", "name": "platform/kimdane-security", "type": "vault_namespace"},    {"id": "byt6iuongd", "name": "kimdane", "type": "ns"},    {"id": "byiuongd", "name": "kimdane", "type": "project"},    {"id": "byiuongr", "name": "dummy-repo", "type": "repo"},    {"id": "byi8hiugd", "name": "kimdane/dummy", "hash": "jno87t7gtvyik7givu", "tag": "latest", "tag_timestamp": "1635589478", "type": "image"},    {"id": "byuon3dgd", "name": "dummy-deployment", "type": "deploy"},    {"id": "byuon3dgds", "name": "dummy-service", "type": "svc"},    {"id": "byuon3dgdi", "name": "dummy-ingress", "host": "dummy.oneadp.com", "port": 8080, "type": "ing"},    {"id": "byuon3dgdp", "name": "dummy-pod-456gh", "type": "pod"},    {"id": "byuon3dgdc", "name": "dummy-container", "ports": [8080], "type": "container"},    {"id": "k8s-cluster1", "name": "k8s-cluster1", "type": "cluster"},    {"id": "byuon", "name": "k8s-cluster1-456ythgfr", "type": "node"}  ],  "links": [    {"source": "k8s-cluster1", "target": "byuon", "value": 1},    {"source": "byuon", "target": "byt6iuongd", "value": 1},    {"source": "byt6iuongd", "target": "byuon3dgd", "value": 1},    {"source": "byuon3dgd", "target": "byuon3dgds", "value": 1},    {"source": "byuon3dgdi", "target": "byuon3dgds", "value": 1},    {"source": "byuon3dgds", "target": "byuon3dgdp", "value": 1},    {"source": "byuon3dgdp", "target": "byuon3dgdc", "value": 1},    {"source": "byiuongr", "target": "byt6i8hiuon3dgd", "value": 2},    {"source": "byiuongd", "target": "byiuongr", "value": 2},    {"source": "byt6i8hiuon3dgd", "target": "byi8hiugd", "value": 1},    {"source": "byi8hiugd", "target": "byuon3dgdc", "value": 2},    {"source": "byuon3dgdc", "target": "byuon3dgdi", "value": 1},    {"source": "byt6iuon3dgd", "target": "byt6iuongd", "value": 0}  ]}');})
.summary('Data Set')
.description('Prints a data set.');
