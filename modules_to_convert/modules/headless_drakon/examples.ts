/**
 * Example usage of the headless DRAKON graph builder
 */

import { DrakonGraphBuilder, DrakonNodeType } from './index';

// Example 1: Simple Linear Flow
function createSimpleFlow() {
  console.log('=== Example 1: Simple Linear Flow ===');
  
  const graph = new DrakonGraphBuilder();
  
  // Build a simple process flow
  const startId = graph.addNode(DrakonNodeType.START, 'Start Process', 100, 50);
  const action1Id = graph.addNode(DrakonNodeType.ACTION, 'Initialize System', 100, 150);
  const action2Id = graph.addNode(DrakonNodeType.ACTION, 'Load Data', 100, 250);
  const endId = graph.addNode(DrakonNodeType.END, 'Complete', 100, 350);
  
  // Connect the nodes
  graph.addConnection(startId, action1Id);
  graph.addConnection(action1Id, action2Id);
  graph.addConnection(action2Id, endId);
  
  console.log('Graph:', graph.getGraph());
  console.log('Stats:', graph.getStats());
  console.log('');
}

// Example 2: Conditional Flow
function createConditionalFlow() {
  console.log('=== Example 2: Conditional Flow ===');
  
  const graph = new DrakonGraphBuilder();
  
  // Build a flow with conditional logic
  const startId = graph.addNode(DrakonNodeType.START, 'Start', 200, 50);
  const inputId = graph.addNode(DrakonNodeType.IO, 'Get User Input', 200, 150);
  const checkId = graph.addNode(DrakonNodeType.IF, 'Valid Input?', 200, 250);
  const processId = graph.addNode(DrakonNodeType.ACTION, 'Process Input', 100, 350);
  const errorId = graph.addNode(DrakonNodeType.ACTION, 'Show Error', 300, 350);
  const endId = graph.addNode(DrakonNodeType.END, 'End', 200, 450);
  
  // Connect nodes
  graph.addConnection(startId, inputId);
  graph.addConnection(inputId, checkId);
  graph.addConnection(checkId, processId); // Yes branch
  graph.addConnection(checkId, errorId);   // No branch
  graph.addConnection(processId, endId);
  graph.addConnection(errorId, endId);
  
  // Print connections from the IF node
  console.log('Connections from IF node:', graph.getConnectionsFrom(checkId));
  console.log('Total nodes:', graph.getNodes().length);
  console.log('');
}

// Example 3: Graph Manipulation
function demonstrateManipulation() {
  console.log('=== Example 3: Graph Manipulation ===');
  
  const graph = new DrakonGraphBuilder();
  
  // Create initial nodes
  const nodeId = graph.addNode(DrakonNodeType.ACTION, 'Original Text', 100, 100);
  console.log('Original node:', graph.getNode(nodeId));
  
  // Update text
  graph.updateNodeText(nodeId, 'Updated Text');
  console.log('After text update:', graph.getNode(nodeId));
  
  // Move node
  graph.moveNode(nodeId, 50, 50, true); // relative move
  console.log('After move:', graph.getNode(nodeId));
  
  // Update styling
  graph.updateNode(nodeId, {
    fill: '#ff6b6b',
    stroke: '#ff0000',
    fontSize: 18,
  });
  console.log('After styling:', graph.getNode(nodeId));
  console.log('');
}

// Example 4: Save and Load
function demonstrateSaveLoad() {
  console.log('=== Example 4: Save and Load ===');
  
  const graph = new DrakonGraphBuilder();
  
  // Build a simple graph
  const start = graph.addNode(DrakonNodeType.START, 'Start', 0, 0);
  const end = graph.addNode(DrakonNodeType.END, 'End', 0, 100);
  graph.addConnection(start, end);
  
  // Export to JSON
  const json = graph.toJSON();
  console.log('Exported JSON:', json);
  
  // Create new graph and load
  const newGraph = new DrakonGraphBuilder();
  newGraph.fromJSON(json);
  console.log('Loaded graph stats:', newGraph.getStats());
  console.log('');
}

// Example 5: Validation
function demonstrateValidation() {
  console.log('=== Example 5: Validation ===');
  
  const graph = new DrakonGraphBuilder();
  
  // Create valid graph
  const node1 = graph.addNode(DrakonNodeType.START, 'Start', 0, 0);
  const node2 = graph.addNode(DrakonNodeType.END, 'End', 0, 100);
  graph.addConnection(node1, node2);
  
  console.log('Valid graph:', graph.validate());
  
  // Manually create invalid state (simulating corruption)
  const graphData = graph.getGraph();
  graph.addConnection('non-existent-node', node2);
  
  console.log('Invalid graph:', graph.validate());
  console.log('');
}

// Example 6: Complex Workflow
function createComplexWorkflow() {
  console.log('=== Example 6: Complex Workflow ===');
  
  const graph = new DrakonGraphBuilder();
  
  // Build a more complex workflow
  const start = graph.addNode(DrakonNodeType.START, 'Start Application', 300, 50);
  const init = graph.addNode(DrakonNodeType.ACTION, 'Initialize', 300, 150);
  const choice = graph.addNode(DrakonNodeType.CHOICE, 'Select Mode', 300, 250);
  const mode1 = graph.addNode(DrakonNodeType.ACTION, 'Process Mode 1', 150, 350);
  const mode2 = graph.addNode(DrakonNodeType.ACTION, 'Process Mode 2', 300, 350);
  const mode3 = graph.addNode(DrakonNodeType.ACTION, 'Process Mode 3', 450, 350);
  const merge = graph.addNode(DrakonNodeType.ACTION, 'Merge Results', 300, 450);
  const output = graph.addNode(DrakonNodeType.IO, 'Save Output', 300, 550);
  const end = graph.addNode(DrakonNodeType.END, 'Complete', 300, 650);
  
  // Connect everything
  graph.addConnection(start, init);
  graph.addConnection(init, choice);
  graph.addConnection(choice, mode1);
  graph.addConnection(choice, mode2);
  graph.addConnection(choice, mode3);
  graph.addConnection(mode1, merge);
  graph.addConnection(mode2, merge);
  graph.addConnection(mode3, merge);
  graph.addConnection(merge, output);
  graph.addConnection(output, end);
  
  const stats = graph.getStats();
  console.log('Complex workflow stats:');
  console.log(`  - Nodes: ${stats.nodeCount}`);
  console.log(`  - Connections: ${stats.connectionCount}`);
  console.log('  - By type:', stats.nodesByType);
  
  // Clone the graph
  const cloned = graph.clone();
  console.log('Cloned graph has same stats:', cloned.getStats());
  console.log('');
}

// Run all examples
if (import.meta.url === `file://${process.argv[1]}`) {
  createSimpleFlow();
  createConditionalFlow();
  demonstrateManipulation();
  demonstrateSaveLoad();
  demonstrateValidation();
  createComplexWorkflow();
}

// Export for use as a module
export {
  createSimpleFlow,
  createConditionalFlow,
  demonstrateManipulation,
  demonstrateSaveLoad,
  demonstrateValidation,
  createComplexWorkflow,
};
