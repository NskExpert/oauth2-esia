<?php

namespace Ekapusta\OAuth2Esia\Security\Signer;

use Ekapusta\OAuth2Esia\Security\Signer;
use Ekapusta\OAuth2Esia\Security\Signer\Exception\SignException;

class OpensslCli extends Signer
{
    private $toolPath;

    /**
     * OpensslCli constructor.
     * @param $certificatePath
     * @param $privateKeyPath
     * @param null $privateKeyPassword
     * @param string $toolPath
     */
    public function __construct(
        $certificatePath,
        $privateKeyPath,
        $privateKeyPassword = null,
        $toolPath = 'openssl'
    ) {
        parent::__construct($certificatePath, $privateKeyPath, $privateKeyPassword);
        $this->toolPath = $toolPath;
    }

    /**
     * @param string $message
     * @return bool|string
     * @throws SignException
     */
    public function sign($message)
    {
        return $this->runParameters([
            'smime -sign -binary -outform DER -noattr',
            '-signer '.escapeshellarg($this->certificatePath),
            '-inkey '.escapeshellarg($this->privateKeyPath),
            '-passin '.escapeshellarg('pass:'.$this->privateKeyPassword),
        ], $message);
    }

    /**
     * @param array $parameters
     * @param $input
     * @return bool|string
     * @throws SignException
     */
    private function runParameters(array $parameters, $input)
    {
        array_unshift($parameters, $this->toolPath);

        return $this->run(implode(' ', $parameters), $input);
    }

    /**
     * Runs command with input from STDIN.
     * @param $command
     * @param $input
     * @return bool|string
     * @throws SignException
     */
    private function run($command, $input)
    {
        $process = proc_open($command, [
            ['pipe', 'r'], // stdin
            ['pipe', 'w'], // stdout
            ['pipe', 'w'], // stderr
        ], $pipes);

        fwrite($pipes[0], $input);
        fclose($pipes[0]);

        $result = stream_get_contents($pipes[1]);
        fclose($pipes[1]);

        $errors = stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        $code = proc_close($process);

        if (0 != $code) {
            $errors = trim($errors) ?: 'unknown';
            throw SignException::signFailedAsOf($errors, $code);
        }

        return $result;
    }
}
