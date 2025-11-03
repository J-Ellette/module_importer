import { DrakonNode, DrakonConnection, DrakonNodeType, DrakonGraph } from './types';

export class DrakonGraphBuilder {
  private nodes: Map<string, DrakonNode> = new Map();
  private connections: Map<string, DrakonConnection> = new Map();
  private nodeCounter: number = 0;

  constructor() {}

  /**
   * Add a node to the graph
   */
  addNode(
    type: DrakonNodeType,
    text: string,
    x: number = 0,
    y: number = 0,
    options?: {
      id?: string;
      width?: number;
      height?: number;
      fill?: string;
      stroke?: string;
      textColor?: string;
      fontSize?: number;
      fitText?: boolean;
    }
  ): string {
    const id = options?.id || `drakon-node-${Date.now()}-${this.nodeCounter++}`;
    
    let width = options?.width || 160;
    let height = options?.height || 60;
    
    // Default height adjustment for IF nodes
    if (type === DrakonNodeType.IF && !options?.height) {
      height = 80;
    }

    const node: DrakonNode = {
      id,
      type,
      text,
      x,
      y,
      width,
      height,
      fill: options?.fill,
      stroke: options?.stroke,
      textColor: options?.textColor,
      fontSize: options?.fontSize,
      fitText: options?.fitText,
    };

    this.nodes.set(id, node);
    return id;
  }

  /**
   * Update node properties
   */
  updateNode(id: string, updates: Partial<Omit<DrakonNode, 'id'>>): boolean {
    const node = this.nodes.get(id);
    if (!node) return false;

    this.nodes.set(id, { ...node, ...updates });
    return true;
  }

  /**
   * Update node position
   */
  moveNode(id: string, x: number, y: number, relative: boolean = false): boolean {
    const node = this.nodes.get(id);
    if (!node) return false;

    if (relative) {
      this.nodes.set(id, { ...node, x: node.x + x, y: node.y + y });
    } else {
      this.nodes.set(id, { ...node, x, y });
    }
    return true;
  }

  /**
   * Update node text
   */
  updateNodeText(id: string, text: string): boolean {
    const node = this.nodes.get(id);
    if (!node) return false;

    this.nodes.set(id, { ...node, text });
    return true;
  }

  /**
   * Resize node
   */
  resizeNode(id: string, width: number, height: number): boolean {
    const node = this.nodes.get(id);
    if (!node) return false;

    this.nodes.set(id, { 
      ...node, 
      width: Math.max(80, width), 
      height: Math.max(40, height) 
    });
    return true;
  }

  /**
   * Remove a node and all its connections
   */
  removeNode(id: string): boolean {
    if (!this.nodes.has(id)) return false;

    this.nodes.delete(id);
    
    // Remove all connections involving this node
    const connectionsToRemove: string[] = [];
    this.connections.forEach((conn, connId) => {
      if (conn.fromId === id || conn.toId === id) {
        connectionsToRemove.push(connId);
      }
    });
    
    connectionsToRemove.forEach(connId => this.connections.delete(connId));
    return true;
  }

  /**
   * Get a node by ID
   */
  getNode(id: string): DrakonNode | undefined {
    return this.nodes.get(id);
  }

  /**
   * Get all nodes
   */
  getNodes(): DrakonNode[] {
    return Array.from(this.nodes.values());
  }

  /**
   * Add a connection between two nodes
   */
  addConnection(fromId: string, toId: string, connectionId?: string): string | null {
    if (!this.nodes.has(fromId) || !this.nodes.has(toId)) {
      return null;
    }

    if (fromId === toId) {
      return null; // No self-connections
    }

    const id = connectionId || `conn-${fromId}-${toId}-${Date.now()}`;
    const connection: DrakonConnection = { id, fromId, toId };
    
    this.connections.set(id, connection);
    return id;
  }

  /**
   * Remove a connection
   */
  removeConnection(id: string): boolean {
    return this.connections.delete(id);
  }

  /**
   * Get a connection by ID
   */
  getConnection(id: string): DrakonConnection | undefined {
    return this.connections.get(id);
  }

  /**
   * Get all connections
   */
  getConnections(): DrakonConnection[] {
    return Array.from(this.connections.values());
  }

  /**
   * Get connections from a specific node
   */
  getConnectionsFrom(nodeId: string): DrakonConnection[] {
    return Array.from(this.connections.values()).filter(c => c.fromId === nodeId);
  }

  /**
   * Get connections to a specific node
   */
  getConnectionsTo(nodeId: string): DrakonConnection[] {
    return Array.from(this.connections.values()).filter(c => c.toId === nodeId);
  }

  /**
   * Get all connections involving a specific node
   */
  getNodeConnections(nodeId: string): DrakonConnection[] {
    return Array.from(this.connections.values()).filter(
      c => c.fromId === nodeId || c.toId === nodeId
    );
  }

  /**
   * Clear all nodes and connections
   */
  clear(): void {
    this.nodes.clear();
    this.connections.clear();
    this.nodeCounter = 0;
  }

  /**
   * Get the complete graph state
   */
  getGraph(): DrakonGraph {
    return {
      nodes: this.getNodes(),
      connections: this.getConnections(),
    };
  }

  /**
   * Load a graph state
   */
  loadGraph(graph: DrakonGraph): void {
    this.clear();
    graph.nodes.forEach(node => {
      this.nodes.set(node.id, { ...node });
    });
    graph.connections.forEach(conn => {
      this.connections.set(conn.id, { ...conn });
    });
  }

  /**
   * Export graph as JSON string
   */
  toJSON(): string {
    return JSON.stringify(this.getGraph(), null, 2);
  }

  /**
   * Import graph from JSON string
   */
  fromJSON(json: string): boolean {
    try {
      const graph = JSON.parse(json) as DrakonGraph;
      this.loadGraph(graph);
      return true;
    } catch (e) {
      console.error('Failed to parse JSON:', e);
      return false;
    }
  }

  /**
   * Validate graph structure
   */
  validate(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Check for orphaned connections
    this.connections.forEach((conn, id) => {
      if (!this.nodes.has(conn.fromId)) {
        errors.push(`Connection ${id} references non-existent source node ${conn.fromId}`);
      }
      if (!this.nodes.has(conn.toId)) {
        errors.push(`Connection ${id} references non-existent target node ${conn.toId}`);
      }
    });

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Clone the graph builder
   */
  clone(): DrakonGraphBuilder {
    const newBuilder = new DrakonGraphBuilder();
    newBuilder.loadGraph(this.getGraph());
    return newBuilder;
  }

  /**
   * Get graph statistics
   */
  getStats(): {
    nodeCount: number;
    connectionCount: number;
    nodesByType: Record<string, number>;
  } {
    const nodesByType: Record<string, number> = {};
    
    this.nodes.forEach(node => {
      nodesByType[node.type] = (nodesByType[node.type] || 0) + 1;
    });

    return {
      nodeCount: this.nodes.size,
      connectionCount: this.connections.size,
      nodesByType,
    };
  }
}
