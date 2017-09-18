<?php

namespace NEX\Csrf;

use PHPUnit\Framework\TestCase;

/**
 * Cette classe sert à implementer des tests.
 */
class CsrfMiddlewareTest extends TestCase
{
    private function makeMiddleware(array &$session = []): ClassCsrfMiddleware
    {
        return new CsrfMiddleware($session);
    }

    /**
     * cette méthode sert à faire une requet via un mock.
     * Retourn une interface requet serveur.
     */
    private function makeRequest(string $method = 'GET', ?array $params = null): ServerRequestInterface
    {
        $request = $this->getMockBuilder(ServerRequestInterface::class)->getMock();

        $request->method('getMethod')->willReturn($method);
        $request->method('getParseBody')->willReturn($params);

        return $request;
    }

    /**
     * Cette méthode sert à.
     */
    private function makeDelegate(): DelegateInterface
    {
        $delegate = $this->getMockBuilder(DelegateInterface::class)->getMock();
        $delegate->method('process')->willReturn($this->makeResponse());

        return $delegate;
    }

    /**
     * cette méthode sert à.
     */
    private function makeResponse(): ResponseInterface
    {
        return  $this->getMockBuilder(ResponseInterface::class)->getMock();
    }

    public function testAcceptValideSession()
    {
        $a = [];
        $b = $this->getMockBuilder(ArrayAccess::class)->getMock();
        $middlewareA = new CsrfMiddleware($a);
        $middlewareB = new CsrfMiddleware($B);
        $this->assertInstanceOf(CsrfMiddleware::class, $middlewareA);
        $this->assertInstanceOf(CsrfMiddleware::class, $middlewareB);
    }

    public function testRejectInvalideSession()
    {
        $this->expectException(\TypeError::class);
        $a = new \stdClass();
        $middlewareA = $this->makeMiddleware($a);
    }

    /**
     * cette fonction sert à tester les données passé en GET.
     */
    public function testGetPass()
    {
        $middleware = $this->makeMiddleware();
        $delegate = $this->makeDelegate();
        $delegate->expects($this->once())->method('process');
        $middleware->process($this->makeRequest('GET'), $delegate);
    }

    /**
     * cette méthode sert à.
     */
    public function testPreventPost()
    {
        $middleware = $this->makeMiddleware();
        $delegate = $this->makeDelegate();
        $delegate->expects($this->never())->method('process');
        $this->expectException(NoCsrfException::class);
        $middleware->process($this->makeRequest('POST'), $delegate);
    }

    /**
     * Cette methode sert à ... quand les tests fait avec un token est réussi.
     */
    public function testPostWithValidToken()
    {
        $middleware = $this->makeMiddleware();
        $token = $middleware->generateToken();
        $delegate = $this->makeDelegate();
        $delegate->expects($this->once())->method('process')->willReturn($this->makeResponse());
        $middleware->process($this->makeRequest('POST', ['_csrf' => $token]), $delegate);
    }

    /**
     * Cette methode sert à ... quand les tests fait avec un token à échoué.
     */
    public function testPostWithInvalidToken()
    {
        $middleware = $this->makeMiddleware();
        $token = $middleware->generateToken();
        $delegate = $this->makeDelegate();
        $delegate->expects($this->never())->method('process');
        $this->expectException(InvalidCsrfException::class);
        $middleware->process($this->makeRequest('POST', ['_csrf' => 'echec']), $delegate);
    }

    public function testPostWithDoubleToken()
    {
        $middleware = $this->makeMiddleware();
        $token = $middleware->generateToken();
        $delegate = $this->makeDelegate();
        $delegate->expects($this->once())->method('process')->willReturn($this->makeResponse());
        $middleware->process($this->makeRequest('POST', ['_csrf' => $token]), $delegate);
        $this->expectException(InvalidCsrfException::class);
        //Fais deux fois la même requet.
        $middleware->process($this->makeRequest('POST', ['_csrf' => $token]), $delegate);
    }

    public function testLimitTokens()
    {
        $session = [];
        $middleware = $this->makeMiddleware($session);
        for ($i = 0; $i < 100; ++$i) {
            $token = $middleware->generateToken();
        }
        $this->assertCount(50, $session[$middleware->getSessionKey()]);
        $this->assertSame($token, $session[$middleware->getSessionKey()][49]);
    }
}
