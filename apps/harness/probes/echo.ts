import { postJson } from "./share";

__qntx.setMessageHandler((message) => {
  __qntx.post(message);
});

postJson({ ready: true });
