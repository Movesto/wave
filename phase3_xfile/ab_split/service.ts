import { spawn } from 'child_process';
export class Svc {
  launchCommand(command: string): any {
    const [exe, ...args] = command.split(' ');
    return spawn(exe, args);
  }
}
