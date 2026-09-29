// The function's source, as the task hands it to the agent (handler index.test).
exports.test = async (event) => {
  console.log("received", JSON.stringify(event));
  return { statusCode: 200, body: JSON.stringify({ ok: true }) };
};
