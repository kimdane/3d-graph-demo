 var baseUrl="/_db/demo/demo/";
  /* global SpriteText */
  /* global THREE */
  /* global dat */
  /* global fetch */
  /* global ForceGraph3D */
  /* global $ */
  
    Array.prototype.unique_nodes = function() {
      if (this == undefined) {
          return [];
      }
      var a = this.concat();
      for(var i=0; i<a.length; ++i) {
	  if(a[i] && a[i]._id == undefined) a[i]._id = a[i].id;
          for(var j=i+1; j<a.length; ++j) {
	      if(a[j] && a[j]._id == undefined) a[j]._id = a[j].id;
              if(a[i] == undefined || a[j] == undefined || a[i].id === a[j].id || a[i]._id === a[j]._id || a[i] === a[j].id || a[j] === a[i].id)
                  a.splice(j--, 1);
          }
      }
      return a;
    };
    
    Array.prototype.unique_links = function() {
      if (this == undefined) {
          return [];
      }
      var a = this.concat();
      for(var i=0; i<a.length; ++i) {
        if (a[i]) {
          for(var j=i+1; j<a.length; ++j) {

              if( //a[i] || 
                (a[i].source == a[j].source && a[i].target == a[j].target) || 
                (a[i].source._id && a[i].target._id && a[i].source._id == a[j].source && a[i].target._id == a[j].target) || 
                (a[j].source._id && a[j].target._id && a[i].source == a[j].source._id && a[i].target == a[j].target._id)
                  ) {
                  a.splice(j--, 1);
                  //console.log("I " + a[i].source._id + " " + a[j].source._id + " J");
            } else {
                  //console.log(a[i]);
                }
          }
        } else {
          a.splice(i, 1);
        }
      }
      return a;
    };

    // function for drawing rounded rectangles
function roundRect(ctx, x, y, w, h, r)
{
    ctx.beginPath();
    ctx.moveTo(x+r, y);
    ctx.lineTo(x+w-r, y);
    ctx.quadraticCurveTo(x+w, y, x+w, y+r);
    ctx.lineTo(x+w, y+h-r);
    ctx.quadraticCurveTo(x+w, y+h, x+w-r, y+h);
    ctx.lineTo(x+r, y+h);
    ctx.quadraticCurveTo(x, y+h, x, y+h-r);
    ctx.lineTo(x, y+r);
    ctx.quadraticCurveTo(x, y, x+r, y);
    ctx.closePath();
    ctx.fill();
	ctx.stroke();
}

function makeTextSprite( message, parameters )
{
	if ( parameters === undefined ) parameters = {};
	
	var fontface = parameters.hasOwnProperty("fontface") ? 
		parameters["fontface"] : "Arial";
	
	var fontsize = parameters.hasOwnProperty("fontsize") ? 
		parameters["fontsize"] : 18;
	
	var borderThickness = parameters.hasOwnProperty("borderThickness") ? 
		parameters["borderThickness"] : 4;
	
	var borderColor = parameters.hasOwnProperty("borderColor") ?
		parameters["borderColor"] : { r:0, g:0, b:0, a:1.0 };
	
	var backgroundColor = parameters.hasOwnProperty("backgroundColor") ?
		parameters["backgroundColor"] : { r:255, g:255, b:255, a:1.0 };

		
	var canvas = document.createElement('canvas');
	var context = canvas.getContext('2d');
	context.font = "Bold " + fontsize + "px " + fontface;
    
	// get size data (height depends only on font size)
	var metrics = context.measureText( message );
	var textWidth = metrics.width;
	
	// background color
	context.fillStyle   = "rgba(" + backgroundColor.r + "," + backgroundColor.g + ","
								  + backgroundColor.b + "," + backgroundColor.a + ")";
	// border color
	context.strokeStyle = "rgba(" + borderColor.r + "," + borderColor.g + ","
								  + borderColor.b + "," + borderColor.a + ")";

	context.lineWidth = borderThickness;
	roundRect(context, borderThickness/2, borderThickness/2, textWidth + borderThickness, fontsize * 1.4 + borderThickness, 6);
	// 1.4 is extra height factor for text below baseline: g,j,p,q.
	
	// text color
	context.fillStyle = "rgba(0, 0, 0, 1.0)";

	context.fillText( message, borderThickness, fontsize + borderThickness);
	
	// canvas contents will be used for a texture
	var texture = new THREE.Texture(canvas);
	texture.needsUpdate = true;

	var spriteMaterial = new THREE.SpriteMaterial( 
		{ map: texture } );
	var sprite = new THREE.Sprite( spriteMaterial );
	sprite.scale.set(100,50,1.0);
	return sprite;	
}



    // controls
    const controls = { 'DAG Orientation': 'td'};
    const gui = new dat.GUI();
    gui.add(controls, 'DAG Orientation', ['td', 'bu', 'lr', 'rl', 'zout', 'zin', 'radialout', 'radialin', null])
      .onChange(orientation => graph && graph.dagMode(orientation));
  
    var sNode = 'missing';
    $.ajax({
      url: baseUrl+'startNode',
      async: false,
      dataType: 'json',
      success: function (response) {
        sNode=response
      }
    });
    var startNode = {'StartNode': sNode};
    console.log("startNode " + startNode.StartNode);

    var undrawnGraph = {nodes:[], links:[]};

    let controller = new function() {  
        this.securityScans=true;
        this.vulnerabilities=true;
        this.artifacts=true;
        this.pods=true;
        this.projects=true;
        this.containers=true;
        this.ingress=true;
        this.service=true;
        this.dockerImages=true;
        this.repositories=true;
        this.users=true;
        this.userGroups=true;
        this.low=true;
        this.medium=true;
        this.high=true;
        this.critical=true;
    }
    
    let f1 = gui.addFolder('Visible Node Types');
    f1.add(controller, 'artifacts').listen().onChange(value => { 
          this.artifacts=value;
          graph && filterGraphNodes(graph, controller);
        });
    f1.add(controller, 'dockerImages').listen().onChange(value => { 
          this.dockerImages=value;
          graph && filterGraphNodes(graph, controller);
    });
    f1.add(controller, 'securityScans').listen().onChange(value => { 
          this.securityScans=value;
          graph && filterGraphNodes(graph, controller);
    });
    f1.add(controller, 'users').listen().onChange(value => { 
          this.users=value;
          graph && filterGraphNodes(graph, controller);
    });  
    f1.add(controller, 'userGroups').listen().onChange(value => { 
          this.userGroups=value;
          graph && filterGraphNodes(graph, controller);
    });  
    f1.add(controller, 'repositories').listen().onChange(value => { 
          this.repositories=value;
          graph && filterGraphNodes(graph, controller);
    });      
    f1.add(controller, 'vulnerabilities').listen().onChange(value => { 
          this.vulnerabilities=value;
          graph && filterGraphNodes(graph, controller);
    });
    
    let f2 = gui.addFolder('Vulnerability Severity');
    f2.add(controller, 'low').listen().onChange(value => { 
          this.low=value;
          graph && filterGraphNodes(graph, controller);
    });
    f2.add(controller, 'medium').listen().onChange(value => { 
          this.medium=value;
          graph && filterGraphNodes(graph, controller);
    });
    f2.add(controller, 'high').listen().onChange(value => { 
          this.high=value;
          graph && filterGraphNodes(graph, controller);
    });
    f2.add(controller, 'critical').listen().onChange(value => { 
          this.critical=value;
          graph && filterGraphNodes(graph, controller);
    });    

    function getSourceAndTargetLinks(nodeId, links) {
      var nodeSources = [];
      var nodeTargets = [];
      var keepLinks = [];
      for (var j=0;j<links.length;j++) {
        if (links[j].source._id == nodeId) nodeSources.push(links[j]);
        else if (links[j].target._id == nodeId) nodeTargets.push(links[j]);
        else keepLinks.push(links[j]);
      }

      return {nodeSources, nodeTargets, keepLinks};
    }
    
    function getUpdatedLinks(sources, targets) {
      var newLinks = [];
      for(var i=0; i<sources.length && i<targets.length; i++) {
        newLinks.push({'source': targets[i].source, 'target': sources[i].target, 'type': 'temp'});
      }
      return newLinks;
    }

    function filterGraphNodes(graph, nodesTypes) {
      let types = ['node','ns','vault_namespace','pod','container','cluster','node','deploy','svc'];
      let severities = [];
      nodesTypes.low && severities.push('Low');
      nodesTypes.medium && severities.push('Medium');
      nodesTypes.high && severities.push('High');
      nodesTypes.critical && severities.push('Critical');
      
      nodesTypes.securityScans && types.push('securityScan');
      nodesTypes.artifacts && types.push('artifact');
      nodesTypes.dockerImages && types.push('image');
      nodesTypes.vulnerabilities && types.push('vulnerability');
      nodesTypes.repositories && types.push('repo');
      nodesTypes.users && types.push('user');
      nodesTypes.projects && types.push('project');
      nodesTypes.ingress && types.push('ing');
      nodesTypes.userGroups && types.push('usergroup');

      var updatedNodes = [];
      let { nodes, links } = graph.graphData();
      nodes = nodes.concat(undrawnGraph.nodes).unique_nodes();
      console.log("links " + links.length);
      links = links.concat(undrawnGraph.links).unique_links();
      console.log("links " + links.length);
      var updatedLinks = [];
      var recalcLinks = [];
      undrawnGraph = {nodes:[], links:[]};
      for (var i=0;i<links.length;i++) {
	  //console.log(links[i].source);
          //if (types.includes(links[i].target.id) && links[i].type != 'temp') {
          if ((types.includes(links[i].target._id.split('/')[0]) || types.includes(links[i].target.type)) && links[i].type != 'temp') {
            updatedLinks.push(links[i]);
          } else {
            recalcLinks.push(links[i]);
          }
      }
      for (var i=0;i<nodes.length;i++) {
          //console.log(nodes[i]?.severity)
          if (types.includes(nodes[i]?.type)) {
            updatedNodes.push(nodes[i]);
          } else {
            undrawnGraph.nodes.push(nodes[i]);
            let {nodeSources, nodeTargets, recalcLinks} = getSourceAndTargetLinks(nodes[i]._id, links);
            undrawnGraph.links = undrawnGraph.links.concat(nodeSources).concat(nodeTargets);
            if (types.length>1) {
              updatedLinks = updatedLinks.concat(getUpdatedLinks(nodeSources, nodeTargets));
            }
          }
      }
      if (types.includes('vulnerability') && severities.length != 4) {
        var newNodes = [];
        var newLinks = [];
        for (var i=0;i<updatedNodes.length;i++) {
          //console.log(nodes[i]?.severity)
          if (severities.includes(updatedNodes[i]?.severity)) {
            let {nodeSources, nodeTargets, recalcLinks} = getSourceAndTargetLinks(updatedNodes[i]._id, updatedLinks);
            newLinks = newLinks.concat(nodeSources);//.concat(nodeTargets);
            newNodes.push(updatedNodes[i]);
          } else if (updatedNodes[i]?.severity != null) {
            undrawnGraph.nodes.push(updatedNodes[i]);
            let {nodeSources, nodeTargets, recalcLinks} = getSourceAndTargetLinks(updatedNodes[i]._id, updatedLinks);
            //newLinks = newLinks.concat(getUpdatedLinks(nodeSources, nodeTargets));
            //console.log("undraw " + nodeSources.concat(nodeTargets)[0]._id); 
            undrawnGraph.links = undrawnGraph.links.concat(nodeSources).concat(nodeTargets);          
          } else {
            let {nodeSources, nodeTargets, recalcLinks} = getSourceAndTargetLinks(updatedNodes[i]._id, updatedLinks);
            newLinks = newLinks.concat(nodeSources);
            newNodes.push(updatedNodes[i]);             
          }
        }
        updatedNodes = newNodes;
        updatedLinks = newLinks;
      }
      
      undrawnGraph = {nodes: undrawnGraph.nodes.unique_nodes(), links: undrawnGraph.links.unique_links()};
      graph.graphData({nodes: updatedNodes.unique_nodes(), links: updatedLinks.unique_links()});
    }
      
    //const gData = {nodes:[{id: 'bad id',_id:'bad/id', name: 'name'}], links:[]};
    //fetch('http://127.0.0.1:8529/_db/_system/getting-started/bi-graph/'+encodeURIComponent(startNode.StartNode)).then(res => res.json()).then(data => { gData['nodes']=data.nodes; gData['links']=data.links });

    // Add a string controller.
    gui.add(startNode, 'StartNode')
      .onFinishChange(node => graph && 
          fetch(baseUrl+'graph/'+encodeURIComponent(node)).then(res => res.json())
              .then(data => (!data) ? null : graph.graphData(data))
          );
    //console.log("gData links " + gData.links.length.toString());
    //console.log("gData nodes " + gData['nodes'].length);
    const elem = document.getElementById('3d-graph');
    let distance = 800;
    let focusedNode = null
    //const ForceGraph3D = require('https://fireclover.imk.im/_db/demo/demo/js/3d-force-graph');
    const graph = ForceGraph3D()
      (elem) // bi-graph
        .jsonUrl(baseUrl+'graph/'+encodeURIComponent(startNode.StartNode))
        .nodeLabel(d => d?.type == 'vulnerability' ? d.description : d.name)
        .linkDirectionalParticles('value')
        .backgroundColor('#000')
        .linkDirectionalParticleSpeed(d => d.value * 0.001)
        .linkWidth(3)
        .linkDirectionalParticleWidth(2)
        //.nodeColor(n =>  n?.type != 'vulnerability' && console.log("node: "+n.name) ? 'red' : null)
        //  if (node._id.split('/')[0] == 'vulnerability') {
        //    return 'red';
        //  }
        //})
        .nodeThreeObject(node => {
          const label = new SpriteText(''+node?.name);
          //label.material.depthWrite = false; // make sprite background transparent
          label.textHeight = 0.25;
          //if (node._id.split('/')[0] != 'vulnerability') {
            const imgTexture = new THREE.TextureLoader().load(baseUrl+'icons/'+node?.type+'.svg');
            const fireTexture = new THREE.TextureLoader().load(baseUrl+'icons/vulnerability.svg');
	    var i, result = "";
  		for (i=0;i<node?.type.length;i++) {
	    		result += node?.type.charCodeAt(i)*15;
    		};
	    const randcolor = "#" + (result % 16777215).toString(16);
            const material = new THREE.SpriteMaterial({ map: imgTexture, color: randcolor });
            const sprite = new THREE.Sprite(material);
            sprite.material.depthWrite = false;
            sprite.scale.set(12, 12);
		if (node?.type === 'artifact') {
	              sprite.scale.set(6, 6);
		}
            label.position.x = label.textHeight * 0.9;
            label.position.y = label.textHeight * 5;
            label.position.z = label.textHeight * 0.9;
              switch(node?.severity) {
                case 'Critical':
		  material.map = fireTexture;
                  material.color.set(0xff00ff);
	          sprite.scale.set(36, 36);
                  break;
                case 'High':
		  material.map = fireTexture;
                  material.color.set(0xff0000);
	          sprite.scale.set(24, 24);
                  break;
                case 'Medium':
		  material.map = fireTexture;
                  material.color.set(0xffaa00);
                  break;  
                case 'Low':
                  material.color.set(0x00ff00);
                  break;                  
                default:
              }
              //const text = makeTextSprite('test', { fontsize: 14, borderColor: {r:255, g:0, b:0, a:1.0}, backgroundColor: {r:255, g:100, b:100, a:0.8} });
              //text.position.x = label.position.x;
              //text.position.y = label.position.y;
              //text.position.z = label.position.z;
              //sprite.add(text);
            
	    sprite.add(label);
            return sprite;
          //}
        })
        //.nodeThreeObjectExtend(true)
        .onNodeRightClick(node => {
          let { nodes, links } = graph.graphData();
          fetch(baseUrl+'bi-graph/'+encodeURIComponent(node._id)).then(res => res.json()).then(data => {
            if (data.nodes &&  data.links) {
              graph.graphData({nodes: nodes.concat(data.nodes).unique_nodes(), links: links.concat(data.links).unique_links()});
            }
            window.open(baseUrl+'node/'+encodeURIComponent(node._id), "_blank");
          });
        })
        .onNodeClick(node => {
          // Aim at node from outside it
          distance = 200;
          const distRatio = 1 + distance/Math.hypot(node.x, node.y, node.z);

          graph.cameraPosition(
            { x: node.x * distRatio, y: node.y * distRatio, z: node.z * distRatio * 2 }, // new position
            node, // lookAt ({ x, y, z })
            3000  // ms transition duration
          );

          //fetch(baseUrl+'node/'+encodeURIComponent(node._id)).then(res => res.json()).then(data => {
          //  console.log(data);
          //  window.open(baseUrl+'node/'+encodeURIComponent(node._id), "_blank");
          //  // let gd = graph.graphData();
          //  // const material = new THREE.SpriteMaterial();
          //  // const sprite = new THREE.Sprite(material);
          //  // const text = makeTextSprite(data[0], { fontsize: 14, borderColor: {r:255, g:0, b:0, a:1.0}, backgroundColor: {r:255, g:100, b:100, a:0.8} });
          //  // sprite.add(text);
          //  //   gd.nodes.push(sprite);
          //  //   graph.graphData(gd);
          //});
              //text.position.x = label.position.x;
              //text.position.y = label.position.y;
              //text.position.z = label.position.z;
              //sprite.add(text);          
          graph.refresh();
        });
        // Spread nodes a little wider
        //graph.d3Force('charge').strength(-240);
        graph.d3Force('charge').strength(-20);

