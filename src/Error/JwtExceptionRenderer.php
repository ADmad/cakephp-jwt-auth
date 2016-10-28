<?php

namespace ADmad\JwtAuth\Error;


use Cake\Error\ExceptionRenderer;

class JwtExceptionRenderer extends ExceptionRenderer
{

    /**
     * @param \ADmad\JwtAuth\Exception\JwtException $exception
     * @return \Cake\Network\Response
     */
    public function jwt($exception)
    {
        $this->controller->set([
            'error' => $exception->getError(),
            'message' => $exception->getMessage(),
            'url' => h($this->controller->request->here()),
            'code' => $exception->getCode(),
            '_serialize' => ['error', 'message', 'code', 'url']
        ]);
        $template = $this->_template($exception, $this->method, 401);
        return $this->_outputMessage($template);
    }

}