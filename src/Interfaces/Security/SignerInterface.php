<?php

namespace Ekapusta\OAuth2Esia\Interfaces\Security;

use Ekapusta\OAuth2Esia\Security\Signer\Exception\SignException;

interface SignerInterface
{
    /**
     * @param string $message
     *
     * @throws SignException
     *
     * @return string
     */
    public function sign($message);
}
