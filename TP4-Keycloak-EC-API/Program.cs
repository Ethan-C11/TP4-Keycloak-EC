
using System.Buffers.Text;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

const string Realm        = "tp-realm";
const string ClientId     = "dotnetapp";
const string ClientSecret = "gaK8wwI25llvAxUEA7a1Ls7lXrTPYVDcgRWokuW2gTxGWPVFf7ecTI0myVoRVOFdkQlFo5E08BR8aw0wAcH0c8";
const string RedirectUri  = "http://localhost:3000/redirect";
const string Issuer       = $"http://localhost:8080/realms/{Realm}";
const string OidcBase     = $"{Issuer}/protocol/openid-connect";

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpClient();
var app = builder.Build();

app.MapGet("/", () => Results.Content(
    "<h1>TP IAM</h1><a href=\"/login\">Se connecter avec Keycloak</a>", "text/html"));


app.MapGet("/login", (HttpContext ctx) =>
{
    // state valeur aléatoire
    var state = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));

    ctx.Response.Cookies.Append("oidc_state", state, new CookieOptions
    {
        HttpOnly = true,
        SameSite = SameSiteMode.Lax,   
        MaxAge   = TimeSpan.FromMinutes(5)
    });

    var url = QueryHelpers.AddQueryString($"{OidcBase}/auth", new Dictionary<string, string?>
    {
        ["client_id"]     = ClientId,
        ["redirect_uri"]  = RedirectUri,
        ["response_type"] = "code",
        ["scope"]         = "openid",
        ["state"]         = state
    });

    return Results.Redirect(url);
});

app.MapGet("/redirect", async (
    HttpContext ctx,
    IHttpClientFactory httpFactory,
    string? code,
    string? state,
    string? session_state,
    string? error,
    string? error_description) =>
{
    if (error is not null)
        return Results.BadRequest(new { error, error_description });

    // Vérification du state (protection CSRF) 
    var expectedState = ctx.Request.Cookies["oidc_state"];
    ctx.Response.Cookies.Delete("oidc_state");

    if (string.IsNullOrEmpty(expectedState) || string.IsNullOrEmpty(state) ||
        !CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expectedState), Encoding.UTF8.GetBytes(state)))
    {
        return Results.BadRequest("state invalide : possible attaque CSRF / réponse non sollicitée.");
    }

    if (string.IsNullOrEmpty(code))
        return Results.BadRequest("Paramètre 'code' manquant.");

    var http = httpFactory.CreateClient();

    // Échange code -> tokens (POST x-www-form-urlencoded, côté backend)
    var form = new Dictionary<string, string>
    {
        ["grant_type"]    = "authorization_code",
        ["client_id"]     = ClientId,
        ["client_secret"] = ClientSecret,
        ["redirect_uri"]  = RedirectUri,
        ["code"]          = code,
        ["state"]         = state,
        ["session_state"] = session_state ?? ""
    };

    var tokenResponse = await http.PostAsync($"{OidcBase}/token", new FormUrlEncodedContent(form));
    var tokenBody = await tokenResponse.Content.ReadAsStringAsync();

    if (!tokenResponse.IsSuccessStatusCode)
        return Results.Content(tokenBody, "application/json", statusCode: (int)tokenResponse.StatusCode);

    var tokens = JsonSerializer.Deserialize<JsonElement>(tokenBody);
    var accessToken = tokens.GetProperty("access_token").GetString()!;
    var idToken     = tokens.GetProperty("id_token").GetString()!;

    // Décodage des JWT
    var accessDecoded = DecodeJwt(accessToken);
    var idDecoded     = DecodeJwt(idToken);

    // (Optionnel) Vérification de la signature de l'id_token
    var signatureValid = await VerifySignatureAsync(idToken, $"{OidcBase}/certs", http);
    var claims = idDecoded.Payload;
    var issuerOk   = claims.GetProperty("iss").GetString() == Issuer;
    var audienceOk = claims.GetProperty("aud").ToString().Contains(ClientId);
    var notExpired = DateTimeOffset.UtcNow.ToUnixTimeSeconds() < claims.GetProperty("exp").GetInt64();

    // Appel du endpoint userinfo avec l'access token
    var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, $"{OidcBase}/userinfo");
    userInfoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    var userInfoResponse = await http.SendAsync(userInfoRequest);
    var userInfo = JsonSerializer.Deserialize<JsonElement>(await userInfoResponse.Content.ReadAsStringAsync());

    return Results.Json(new
    {
        id_token = new { idDecoded.Header, idDecoded.Payload },
        access_token = new { accessDecoded.Header, accessDecoded.Payload },
        verification = new { signatureValid, issuerOk, audienceOk, notExpired },
        userinfo = userInfo
    }, new JsonSerializerOptions { WriteIndented = true });
});

app.Run("http://localhost:3000");


// Un JWT = header.payload.signature, chaque partie étant en Base64URL.
static (JsonElement Header, JsonElement Payload) DecodeJwt(string jwt)
{
    var parts = jwt.Split('.');
    return (
        JsonSerializer.Deserialize<JsonElement>(Base64Url.DecodeFromChars(parts[0])),
        JsonSerializer.Deserialize<JsonElement>(Base64Url.DecodeFromChars(parts[1]))
    );
}

// Vérifie la signature  à partir de la clé publique publiée par Keycloak.
static async Task<bool> VerifySignatureAsync(string jwt, string jwksUrl, HttpClient http)
{
    var parts = jwt.Split('.');
    var header = JsonSerializer.Deserialize<JsonElement>(Base64Url.DecodeFromChars(parts[0]));

    if (header.GetProperty("alg").GetString() != "RS256")
        return false; 

    var kid  = header.GetProperty("kid").GetString();
    var jwks = await http.GetFromJsonAsync<JsonElement>(jwksUrl);

    foreach (var key in jwks.GetProperty("keys").EnumerateArray())
    {
        if (key.GetProperty("kid").GetString() != kid) continue;

        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus  = Base64Url.DecodeFromChars(key.GetProperty("n").GetString()!),
            Exponent = Base64Url.DecodeFromChars(key.GetProperty("e").GetString()!)
        });

        var signedData = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
        var signature  = Base64Url.DecodeFromChars(parts[2]);

        return rsa.VerifyData(signedData, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    return false;
}