declare namespace zeek {

  interface HandlerOptions {
    priority?: number;
  }

  type EventHandler = (...args: any) => void;
  function on(name: string, handler: EventHandler): void;
  function on(name: string, options: HandlerOptions, handler: EventHandler): void;

  type HookHandler = (...args: any) => boolean|void;
  function hook(name: string, handler: HookHandler): void;
  function hook(name: string, options: HandlerOptions, handler: HookHandler): void;

  function invoke(name: string, args?: any[]): any;

  function event(name: string, args?: any[]): void;

  const ATTR_LOG: number;
  type AttributeMask = number;
  function select_fields(rec: object, mask: AttributeMask): object;

  function flatten(rec: object): object;

  const global_vars: {[name: string]: any};
}
