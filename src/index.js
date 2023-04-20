const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

export default {
  async fetch(request, env) {
    return await handleRequest(request, env).catch(
      (err) => new Response(err.stack, { status: 500 })
    );
  },
};

async function handleRequest(request, env) {
  const { pathname } = new URL(request.url);

  if (pathname.startsWith("/signedurl")) {
    const { searchParams } = new URL(request.url);
    let tokenId = searchParams.get("tokenId");
    let name = searchParams.get("name");
    let duration = searchParams.get("duration");
    let walletAddress = searchParams.get("walletAddress");

    const metadata = { name, duration };
    const urlEncodedMetadata = encodeURIComponent(JSON.stringify(metadata));

    const unsignedUrl =
      env.MOONPAY_BASE_URL +
      `?apiKey=${env.PUBLIC_MOONPAY_KEY}` +
      `&contractAddress=${env.NAMEWRAPPER_CONTRACT_ADDRESS}` +
      `&tokenId=${tokenId}` +
      `&metadata=${urlEncodedMetadata}` +
      `&externalTransactionId=${crypto.randomUUID()}` +
      `&walletAddress=${walletAddress}`;

    const dataToAuthenticate = new URL(unsignedUrl).search;

    const encoder = new TextEncoder();
    const secretKeyData = encoder.encode(env.SECRET_MOONPAY_KEY);
    const key = await crypto.subtle.importKey(
      "raw",
      secretKeyData,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const mac = await crypto.subtle.sign(
      "HMAC",
      key,
      encoder.encode(dataToAuthenticate)
    );

    let base64Mac = btoa(String.fromCharCode(...new Uint8Array(mac)));
    // must convert "+" to "-" as urls encode "+" as " "
    base64Mac = base64Mac.replaceAll("+", "-");

    const urlWithSignature = `${unsignedUrl}&signature=${encodeURIComponent(
      base64Mac
    )}`;

    return new Response(urlWithSignature, {
      headers: { ...corsHeaders },
    });
  }

  if (pathname.startsWith("/transactionInfo")) {
    const { searchParams } = new URL(request.url);
    let externalTransactionId = searchParams.get("externalTransactionId");

    const response = await fetch(
      `https://api.moonpay.com/v1/transactions?limit=1&externalTransactionId=${externalTransactionId}`,
      {
        headers: {
          Authorization: `Api-Key ${env.SECRET_MOONPAY_KEY}`,
        },
      }
    );
    const result = await response.json();
    return new Response(JSON.stringify(result), {
      headers: { ...corsHeaders },
    });
  }
}
