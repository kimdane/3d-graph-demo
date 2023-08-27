const uuid = function() {
        return String.fromCharCode(Math.random()*26+97)+
        String.fromCharCode(Math.random()*26+97)+
        String.fromCharCode(Math.random()*26+97)+
        String.fromCharCode(Math.random()*26+97)+
        String.fromCharCode(Math.random()*26+97)+
        String.fromCharCode(Math.random()*26+97)+
        String.fromCharCode(Math.random()*26+97)+
        String.fromCharCode(Math.random()*26+97)+
        String.fromCharCode(Math.random()*26+97)+
        String.fromCharCode(Math.random()*26+97)+
        String.fromCharCode(Math.random()*26+97)+
        String.fromCharCode(Math.random()*26+97)+
        String.fromCharCode(Math.random()*26+97)+
        String.fromCharCode(Math.random()*26+97);
};

const projectList = [
"Calculator",
"To-do list",
"Linear layout app",
"Expense tracker",
"Sudoku game",
"URL shortener",
"Tax forecaster",
"Random name generator",
"Blackjack game",
"Timer",
"URL encoder or decoder",
"Bill splitter",
"Tax forecaster",
"Relative layout app",
"Movie theater showtime finder",
"Game character generator",
"Net worth calculator",
"Real-time messaging system",
"Internet speed test",
"Deal finder",
"Music recommender",
"Camera motion sensing system",
"Note taker",
"Online learning platform",
"Charity finder",
"Interactive fiction game",
"Video chat program",
"Tic Tac Toe game",
"Data leakage detection system",
"Scavenger hunt app",
"Event planner",
"Table layout app",
"Automated payroll system",
"Solitaire game",
"Chatbot",
"Collaboration tool",
"Content management system",
"Cipher maker",
"Social media site",
"Business account management software",
"Pixel art generator",
"Flashcard app",
"Question and answer platform",
"Virtual interior design program",
"Fitness tracker",
"Food or goods delivery app",
"E-commerce website",
"Algorithm visualizer",
"Chess game",
];

const projectTypes = [
["frontend", "backend", "db"],
["Worker", "UX", "API", "MongoDB", "IntegrationBus"],
["app", "react", "nginx", "enclave", "varnish"],
["web", "service", "orchestrator", "DataMart"],
["ThirdPartyService", "FrontEnd", "BackEnd", "DataBase"],
["WebServer", "MobileServer", "AppServer", "DbCache", "SQL", "BusinessRulesService", "RulesEngine"],
];

const nodeJsDeps = [
"dotenv",
"react",
"typescript",
"aws-sdk",
"angular",
"underscore",
"express",
"core",
"request",
"socket.io",
"multer",
"jsonwebtoken",
"mocca",
"jest",
"bcrypt",
"lodash",
"moment",
"dotenv",
].map(dep => {return {id: uuid(), name: dep, type: "artifact"}});

const pythonDeps = [
"boto3",
"botocore",
"requests",
"django",
"flask",
"mongodb",
"twisted",
"beautifulsoup4",
"selenium",
"numpy",
"pandas",
"matplotlib",
"nltk",
"opencv",
"tensorflow",
"keras",
"pytorch",
"pyqt5",
].map(dep => {return {id: uuid(), name: dep, type: "artifact"}});

const getContainers = function(source, name) {
        const nodes = [];
        const links = [];
        for (var i=0; i< Math.random()*8+1; i++) {
                const id = uuid();
                nodes.push({"id": id, "name": name, "ports": [8080], "type": "container"});
                links.push({"source": source, target: id, value: 1});
        }
	return {nodes, links};
};

const getImage = function(source, name, project) {
        const id = uuid();
        const {nodes, links} = getContainers(id, name);
        return {
                nodes: [...nodes, {"id": id, "name": project+"/"+name, "tag": "latest", "tag_timestamp": Math.floor(1635589478+Math.random()*1000000), "type": "image"}],
                links: [...links, {"source": source, target: id, value: 1}],
        };
};

const getDependencies = function(source, runtime) {
        const deps = runtime == "python-3.10" ? pythonDeps : nodeJsDeps;
        const nodes = [];
        const links = [];
        for (let i=0; i< Math.random()*15+1; i++) {
                const index = deps.length * Math.random();
                nodes.push(deps[index]);
                links.push({"source": source, target: deps[index]?.id, value: Math.ceil(Math.random()*3)});
        }
	return {nodes, links};
}

const getArtifact = function(source, name, project) {
        const id = uuid();
        const runtime = (Math.random()*1 > 0.5) ? "python-3.10" : "nodejs-18.x";
        const image = getImage(id, name, project);
        const deps = getDependencies(id, runtime);
        return {
                nodes: [...image.nodes, ...deps.nodes, {id: id, name: project+"."+name, type: "artifact"}],
                links: [...image.links, ...deps.links, {source: source, target: id, value: 1}],
        };
};

const getRepo = function(source, name, project) {
        const id = uuid();
        const {nodes, links} = getArtifact(id, name, project);
        return {
                nodes: [...nodes, {id: id, name: name, type: "repository"}],
                links: [...links, {source: source, target: id, value: Math.ceil(Math.random()*3)}],
        };
}

const getProject = function(source, name) {
        const id = uuid();
	const repoNames = projectTypes[Math.floor(Math.random()*projectTypes.length)];
        const nodes = [{id: id, name: name, type: "project"}];
        const links = [];
	repoNames.forEach(r => {
	        const repo = getRepo(id, r, name);
		nodes.push(...repo.nodes);
		links.push(...repo.links);
	});
	return {nodes, links};
}

const getProjects = function() {
        const nodes = [];
        const links = [];
	projectList.forEach(p => {
	        const project = getProject(null, p);
		nodes.push(...project.nodes);
		links.push(...project.links);
	});
	return {nodes, links};
}

console.log("\n"+JSON.stringify(getProjects())+"\n");
const data = '';
