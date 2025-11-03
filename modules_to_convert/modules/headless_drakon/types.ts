export enum DrakonNodeType {
  START = 'START',
  END = 'END',
  ACTION = 'ACTION',
  IF = 'IF',
  CHOICE = 'CHOICE',
  IO = 'IO',
}

export interface DrakonNode {
  id: string;
  type: DrakonNodeType;
  text: string;
  x: number;
  y: number;
  width: number;
  height: number;
  // styling
  fill?: string;
  stroke?: string;
  textColor?: string;
  fontSize?: number;
  fitText?: boolean;
}

export interface DrakonConnection {
  id: string;
  fromId: string;
  toId: string;
}

export interface DrakonGraph {
  nodes: DrakonNode[];
  connections: DrakonConnection[];
}
