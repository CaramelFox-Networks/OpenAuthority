export async function onRequest(context) {
  return context.env.openauthority-api.fetch(context.request);
}
