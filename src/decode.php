<?php

require_once 'vendor/autoload.php';

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\KeyManagement\JWKFactory;

const SECRET_KEY = '0191a7be-6cd0-7bb6-8f53-eb2677704366';
const PAYLOAD = 'eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.pEwqiuEPvvHCthYag8ox-izKlVilk_sTlmE8BTz21DlwIyYOjN8mZgAejrRJcFiCdlM2fnUNTU3an9cLPNvLYFrnyn-t0M1j.FTlqEcUsEOU0_Wz-z20jcQ.zRyB6rqUNLBwwcw2XjKAT0y-EU5jPPUuakZnE39bOHzxEK2pNYsWgaoQJL8BAf5TVEwNTNWtNDhUrKlKBmHbebmWKGj_kZGxisSRvY7NcJ-iNO9irMR-cfn1TVxgB4TeCaeAoaTcDVqfeXEtDH6krNvTnfKc21UDhirK56E2Wr-FDHC5V6V3XORfNnOWYsw8AGGcFD1cgVn-gWcbUAsF03v3mSwJ5tCbRZNQRMbFutkbw9XxbUAmuU7rNl0o8EPlhirrVeed4daRyxIBOskIekgqTOun8tsN--gjcMxLPIQ.E58uUhk3kyaacwW6hLeji2otaCck22DCQq46VQXoimw';

/**
 * @return array{
 *     request_id: string,
 *     autowise_id: string,
 *     event_date: string,
 *     event: string,
 *     context: array<string, mixed>
 * }
 */
function decodeWebhook(string $payload, string $secretKey): array
{
    // Create the key
    $jwk = JWKFactory::createFromSecret($secretKey, [
        'alg' => 'A256KW',
        'enc' => 'A256CBC-HS512',
    ]);

    $algorithmManager = new AlgorithmManager([
        new A256KW(),
        new A256CBCHS512(),
    ]);
    $jweSerializer = new CompactSerializer();
    $jweDecrypter = new JWEDecrypter($algorithmManager);
    $serializerManager = new JWESerializerManager([
        $jweSerializer,
    ]);

    $jwk = JWKFactory::createFromSecret($secretKey, [
        'alg' => 'A256KW',
        'enc' => 'A256CBC-HS512',
    ]);

    $jwe = $serializerManager->unserialize($payload);

    // Decrypt the JWE
    $success = $jweDecrypter->decryptUsingKey($jwe, $jwk, 0);

    if (! $success) {
        throw new \RuntimeException('Failed to decrypt the JWE');
    }

    // Get the payload
    $payload = $jwe->getPayload();

    if ($payload === null) {
        throw new \LogicException('Invalid secret');
    }

    // Decode the JSON payload
    $decodedPayload = json_decode($payload, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new \LogicException('Failed to decode JSON payload.');
    }

    // Validate the payload structure
    foreach (['request_id', 'autowise_id', 'event_date', 'event', 'context'] as $key) {
        if (!isset($decodedPayload[$key])) {
            throw new \RuntimeException("Missing required key in payload: {$key}");
        }
    }

    if (!is_array($decodedPayload['context'])) {
        throw new \RuntimeException("The 'context' field must be an array");
    }

    return $decodedPayload;
}

try {
    $decodedWebhook = decodeWebhook(PAYLOAD, SECRET_KEY);
    print_r($decodedWebhook);
} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}
