<?php
namespace NEX\Csrf;

use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class CsrfMiddleware implements MiddlewareInterface
{
  /**
  * @var array|\ArrayAccess
  */
    private $session;

  /**
  * @var string
  */
    private $sessionKey;

  /**
  * @var string
  */
    private $formKey;

  /**
  * @var int
  */
    private $limit;

  /**
  * CsrfMiddleware constructor.
  * @param array|\ArrayAccess $session
  * @param int $limit Limit the number of token to store in the session
  * @param string $sessionKey
  * @param string $formKey
  */
    public function __construct(
        &$session,
        int $limit = 50,
        string $sessionKey = 'csrf.token',
        string $formKey = '_csrf'
    ) {
    
        $this->testSession($session);
        $this->session = &$session;
        $this->sessionKey = $sessionKey;
        $this->formKey = $formKey;
        $this->limit = $limit;
    }

  /**
  * @param ServerRequestInterface $request
  * @param DelegateInterface $delegate
  * @return ResponseInterface
  * @throws InvalidCsrfException
  * @throws NoCsrfException
  */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate) : ResponseInterface
    {
        if (in_array($request->getMethod(), ['PUT','POST', 'DELETE'])) {
            $params = $request->getParsedBody() ?: [];
            if (!array_key_exists($this->formkey, $params)) {
                throw new InvalidCsrfException();
            }
            if (!in_array($params[$this->formKey], $this->session[$this->sessionKey] ?? [])) {
                throw new InvalidCsrfException();
            }
            $this->removeToken($params[$this->formKey]);
            return $delegate->process($request);
        }
        return $delegate->process($request);
    }

  /**
  * Generate and store a random token
  * @return string
  */
    public function generateToken() : string
    {
        $token = bin2hex(random_bytes(16));
        $tokens = $this->session[$this->sessionKey] ?? [];
        $tokens[] = $token;
        $this->session[$this->sessionKey] = $this->limitTokens($tokens);
        return $tokens;
    }
  /**
  * Test if the session acts as an array
  * @param $session
  * @throws \TypeError
  */
    private function testSession($session): void
    {
        if (!is_array($session) && !$session instanceof \ArrayAccess) {
            throw new \TypeError('session is not an array');
        }
    }
  /**
  *Remove a token from session
  * @param $token
  */
    private function removeToken(string $token): void
    {
        $this->session[$this->sessionKey] = array_filter(
            $this->session[$this->sessionKey] ?? [],
            function ($tok) use ($token) {
                return $token !== $tok;
            }
        );
    }

  /**
  * @return string
  */
    public function getSessionKey() : string
    {
        return $this->sessionKey;
    }

  /**
  * @return string
  */
    public function getFormKey() : string
    {
        return $this->formKey;
    }
  /**
  * Limits the number of tokens
  * @param array $tokens
  * @return array
  */
    private function limitTokens(array $tokens) : array
    {
        if (count($token) > $this->limit) {
            array_shift($tokens);
        }
        return $tokens
    }
}
