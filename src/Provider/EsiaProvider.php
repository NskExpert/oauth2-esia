<?php

namespace Ekapusta\OAuth2Esia\Provider;

use Ekapusta\OAuth2Esia\Interfaces\Provider\ProviderInterface;
use Ekapusta\OAuth2Esia\Interfaces\Security\SignerInterface;
use Ekapusta\OAuth2Esia\Interfaces\Token\ScopedTokenInterface;
use Ekapusta\OAuth2Esia\Security\Signer\Exception\SignException;
use Ekapusta\OAuth2Esia\Token\EsiaAccessToken;
use Exception;
use InvalidArgumentException;
use Lcobucci\JWT\Parsing\Encoder;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use LogicException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Ramsey\Uuid\Uuid;

/**
 * Class EsiaProvider
 * @package Ekapusta\OAuth2Esia\Provider
 */
class EsiaProvider extends AbstractProvider implements ProviderInterface
{
    use BearerAuthorizationTrait;

    const RESOURCES = __DIR__.'/../../resources/';

    protected $defaultScopes = ['openid', 'fullname'];

    protected $remoteUrl = 'https://esia.gosuslugi.ru';

    protected $remoteCertificatePath = self::RESOURCES.'esia.prod.cer';

    /**
     * @var SignerInterface
     */
    private $signer;

    /**
     * @var Encoder
     */
    private $encoder;

    /**
     * EsiaProvider constructor.
     * @param array $options
     * @param array $collaborators
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        parent::__construct($options, $collaborators);
        if (!filter_var($this->remoteUrl, FILTER_VALIDATE_URL)) {
            throw new InvalidArgumentException('Remote URL is not provided!');
        }
        if (!file_exists($this->remoteCertificatePath)) {
            throw new InvalidArgumentException('Remote certificate is not provided!');
        }

        if (isset($collaborators['signer']) && $collaborators['signer'] instanceof SignerInterface) {
            $this->signer = $collaborators['signer'];
            $this->encoder = new Encoder();
        } else {
            throw new InvalidArgumentException('Signer is not provided!');
        }
    }

    /**
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return $this->getUrl('/aas/oauth2/ac');
    }

    /**
     * @param array $options
     * @return array
     * @throws SignException
     */
    protected function getAuthorizationParameters(array $options)
    {
        $options = [
            'access_type' => 'online',
            'approval_prompt' => null,
            'timestamp' => $this->getTimeStamp(),
        ] + parent::getAuthorizationParameters($options);

        return $this->withClientSecret($options);
    }

    /**
     * @param array $params
     *
     * @return array
     * @throws SignException
     */
    private function withClientSecret(array $params)
    {
        $message = $params['scope'].$params['timestamp'].$params['client_id'].$params['state'];
        $signature = $this->signer->sign($message);
        $params['client_secret'] = $this->encoder->base64UrlEncode($signature);

        return $params;
    }

    /**
     * @param int $length
     * @return string
     * @throws Exception
     */
    protected function getRandomState($length = 32)
    {
        return Uuid::uuid4()->toString();
    }

    /**
     * @return string
     * @throws Exception
     */
    public function generateState()
    {
        return $this->getRandomState();
    }

    /**
     * @return false|string
     */
    private function getTimeStamp()
    {
        return date('Y.m.d H:i:s O');
    }

    /**
     * @param array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->getUrl('/aas/oauth2/te');
    }

    /**
     * @param AccessToken $token
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        if (!$token instanceof ScopedTokenInterface) {
            throw new LogicException('Токен должен реализовывать интерфейс ' . ScopedTokenInterface::class);
        }
        $embeds = $this->getResourceOwnerEmbeds($token);

        return $this->getUrl('/rs/prns/'.$token->getResourceOwnerId().'?embed=('.implode(',', $embeds).')');
    }

    /**
     * @param ScopedTokenInterface $token
     * @return array
     */
    private function getResourceOwnerEmbeds(ScopedTokenInterface $token)
    {
        $allowedScopes = $token->getScopes();

        $embedsToScopes = [
            'contacts.elements' => [
                'contacts',
                'email',
                'mobile',
            ],
            'addresses.elements' => [
                'contacts',
            ],
            'documents.elements' => [
                'id_doc',
                'medical_doc',
                'military_doc',
                'foreign_passport_doc',
                'drivers_licence_doc',
                'birth_cert_doc',
                'residence_doc',
                'temporary_residence_doc',
            ],
            'vehicles.elements' => [
                'vehicles',
            ],
            'organizations.elements' => [
                'usr_org',
            ],
        ];

        $allowedEmbeds = [];
        foreach ($embedsToScopes as $embed => $scopes) {
            if (count(array_intersect($allowedScopes, $scopes))) {
                $allowedEmbeds[] = $embed;
            }
        }

        return $allowedEmbeds;
    }

    /**
     * @param $path
     * @return string
     */
    private function getUrl($path)
    {
        return $this->remoteUrl.$path;
    }

    /**
     * @return array
     */
    protected function getDefaultScopes()
    {
        return $this->defaultScopes;
    }

    /**
     * @return string
     */
    protected function getScopeSeparator()
    {
        return ' ';
    }

    /**
     * @param array $params
     * @return RequestInterface
     * @throws SignException
     * @throws Exception
     */
    protected function getAccessTokenRequest(array $params)
    {
        $params = $params + [
            'scope' => 'openid',
            'state' => $this->getRandomState(),
            'timestamp' => $this->getTimeStamp(),
            'token_type' => 'Bearer',
        ];

        return parent::getAccessTokenRequest($this->withClientSecret($params));
    }

    /**
     * @param ResponseInterface $response
     * @param array|string $data
     * @throws IdentityProviderException
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if ($response->getStatusCode() >= 400 || isset($data['error'])) {
            throw new IdentityProviderException(
                isset($data['error']) ? $data['error'] : $response->getReasonPhrase(),
                $response->getStatusCode(),
                (string) $response->getBody()
            );
        }
    }

    /**
     * @param array $response
     * @param AbstractGrant $grant
     * @return EsiaAccessToken|AccessTokenInterface
     */
    protected function createAccessToken(array $response, AbstractGrant $grant)
    {
        return new EsiaAccessToken($response, $this->remoteCertificatePath);
    }

    /**
     * @param array $response
     * @param AccessToken $token
     * @return GenericResourceOwner|ResourceOwnerInterface
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        $response = ['resourceOwnerId' => $token->getResourceOwnerId()] + $response;

        return new GenericResourceOwner($response, 'resourceOwnerId');
    }
}
