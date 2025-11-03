# Headless DRAKON Graph Builder

A headless, framework-agnostic module for building and managing DRAKON flowchart graphs. This module provides the core graph-building functionality without any GUI dependencies.

## Installation

Since this is part of the DRAKON Chart Editor project, you can import it directly:

```typescript
import { DrakonGraphBuilder, DrakonNodeType } from './headless_drakon';
```

## Usage

### Basic Example

```typescript
import { DrakonGraphBuilder, DrakonNodeType } from './headless_drakon';

// Create a new graph builder
const graph = new DrakonGraphBuilder();

// Add nodes
const startId = graph.addNode(DrakonNodeType.START, 'Begin Process', 100, 50);
const actionId = graph.addNode(DrakonNodeType.ACTION, 'Process Data', 100, 150);
const endId = graph.addNode(DrakonNodeType.END, 'End Process', 100, 250);

// Connect nodes
graph.addConnection(startId, actionId);
graph.addConnection(actionId, endId);

// Get the complete graph
const graphData = graph.getGraph();
console.log(graphData);
```

### Advanced Features

#### Update Node Properties

```typescript
// Update text
graph.updateNodeText(actionId, 'New Action Text');

// Move node (absolute)
graph.moveNode(actionId, 200, 200);

// Move node (relative)
graph.moveNode(actionId, 10, 10, true);

// Resize node
graph.resizeNode(actionId, 200, 80);

// Update multiple properties
graph.updateNode(actionId, {
  text: 'Updated Text',
  fill: '#ff0000',
  stroke: '#00ff00',
  fontSize: 16
});
```

#### Query Graph Structure

```typescript
// Get all nodes
const allNodes = graph.getNodes();

// Get specific node
const node = graph.getNode(nodeId);

// Get all connections
const allConnections = graph.getConnections();

// Get connections from a node
const outgoing = graph.getConnectionsFrom(nodeId);

// Get connections to a node
const incoming = graph.getConnectionsTo(nodeId);

// Get all connections involving a node
const allNodeConnections = graph.getNodeConnections(nodeId);
```

#### Remove Elements

```typescript
// Remove a node (also removes all its connections)
graph.removeNode(nodeId);

// Remove a connection
graph.removeConnection(connectionId);

// Clear entire graph
graph.clear();
```

#### Save and Load

```typescript
// Export to JSON
const json = graph.toJSON();
console.log(json);

// Save to file (Node.js)
import fs from 'fs';
fs.writeFileSync('graph.json', json);

// Load from JSON
const loaded = graph.fromJSON(json);
if (!loaded) {
  console.error('Failed to load graph');
}

// Load graph state
graph.loadGraph({
  nodes: [...],
  connections: [...]
});
```

#### Validation

```typescript
// Validate graph structure
const validation = graph.validate();
if (!validation.valid) {
  console.error('Graph validation errors:', validation.errors);
}
```

#### Statistics

```typescript
// Get graph statistics
const stats = graph.getStats();
console.log(`Nodes: ${stats.nodeCount}`);
console.log(`Connections: ${stats.connectionCount}`);
console.log('Nodes by type:', stats.nodesByType);
```

#### Clone Graph

```typescript
// Create a copy of the graph
const clonedGraph = graph.clone();
```

## API Reference

### DrakonGraphBuilder

#### Methods

- `addNode(type, text, x?, y?, options?)` - Add a node and return its ID
- `updateNode(id, updates)` - Update node properties
- `moveNode(id, x, y, relative?)` - Move a node
- `updateNodeText(id, text)` - Update node text
- `resizeNode(id, width, height)` - Resize a node
- `removeNode(id)` - Remove a node and its connections
- `getNode(id)` - Get a node by ID
- `getNodes()` - Get all nodes
- `addConnection(fromId, toId, connectionId?)` - Add a connection
- `removeConnection(id)` - Remove a connection
- `getConnection(id)` - Get a connection by ID
- `getConnections()` - Get all connections
- `getConnectionsFrom(nodeId)` - Get outgoing connections
- `getConnectionsTo(nodeId)` - Get incoming connections
- `getNodeConnections(nodeId)` - Get all connections involving a node
- `clear()` - Clear the graph
- `getGraph()` - Get complete graph state
- `loadGraph(graph)` - Load a graph state
- `toJSON()` - Export to JSON string
- `fromJSON(json)` - Import from JSON string
- `validate()` - Validate graph structure
- `clone()` - Clone the graph builder
- `getStats()` - Get graph statistics

### Node Types

- `DrakonNodeType.START` - Start/entry point
- `DrakonNodeType.END` - End/exit point
- `DrakonNodeType.ACTION` - Action/process step
- `DrakonNodeType.IF` - Conditional/decision
- `DrakonNodeType.CHOICE` - Multiple choice
- `DrakonNodeType.IO` - Input/output operation

### Types

```typescript
interface DrakonNode {
  id: string;
  type: DrakonNodeType;
  text: string;
  x: number;
  y: number;
  width: number;
  height: number;
  fill?: string;
  stroke?: string;
  textColor?: string;
  fontSize?: number;
  fitText?: boolean;
}

interface DrakonConnection {
  id: string;
  fromId: string;
  toId: string;
}

interface DrakonGraph {
  nodes: DrakonNode[];
  connections: DrakonConnection[];
}
```

## Use Cases

This headless module can be used in:

- Backend services that generate flowcharts
- Command-line tools for diagram manipulation
- API endpoints that serve graph data
- Testing and validation tools
- Graph analysis and transformation pipelines
- Integration with other visualization libraries
- Automated diagram generation from code or specifications

## License

Part of the DRAKON Chart Editor project.
