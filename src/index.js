const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export default {
  async fetch(request, env) {
    return await handleRequest(request, env).catch(
      () => new Response(JSON.stringify({ error: "Internal server error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      })
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
    //test

    const metadata = { name, duration };
    const urlEncodedMetadata = encodeURIComponent(JSON.stringify(metadata));

    const unsignedUrl =
      env.MOONPAY_BASE_URL +
      `?apiKey=${env.PUBLIC_MOONPAY_KEY}` +
      `&contractAddress=${env.NAMEWRAPPER_CONTRACT_ADDRESS}` +
      `&tokenId=${encodeURIComponent(tokenId)}` +
      `&metadata=${urlEncodedMetadata}` +
      `&externalTransactionId=${crypto.randomUUID()}` +
      `&walletAddress=${encodeURIComponent(walletAddress)}`;

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

    if (!externalTransactionId || !UUID_RE.test(externalTransactionId)) {
      return new Response(
        JSON.stringify({ error: "Valid externalTransactionId is required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const response = await fetch(
      `https://api.moonpay.com/v1/transactions?limit=1&externalTransactionId=${encodeURIComponent(externalTransactionId)}`,
      {
        headers: {
          Authorization: `Api-Key ${env.SECRET_MOONPAY_KEY}`,
        },
      }
    );
    const result = await response.json();

    // Only return fields the frontend needs — don't proxy sensitive payment details
    if (!Array.isArray(result)) {
      return new Response(
        JSON.stringify({ error: "Transaction not found" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const sanitized = result.map(tx => ({
      id: tx.id,
      status: tx.status,
      createdAt: tx.createdAt,
    }));

    return new Response(JSON.stringify(sanitized), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
}
