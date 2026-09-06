import { Svc } from './service';
class Ctrl {
  svc = new Svc();
  handle(@Body() data): any {
    return this.svc.launchCommand(data.command);
  }
}
