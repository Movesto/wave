import { spawn } from 'child_process';
class C {
  handle(@Body() data): any {
    const command = data.command;
    const [exe, ...args] = command.split(' ');
    return spawn(exe, args);
  }
}
