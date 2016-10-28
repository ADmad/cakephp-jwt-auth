<?php
namespace ADmad\JwtAuth\Exception;

use Cake\Network\Exception\UnauthorizedException;

class JwtException extends UnauthorizedException
{

    /**
     * Identifies the error
     * @var string
     */
    protected $_error;

    /**
     * JwtException constructor.
     * @param null $message
     * @param string $error
     * @param int $code
     */
    public function __construct($message = null, $error = 'invalid_token', $code = 401)
    {
        parent::__construct($message, $code);
        $this->_error = $error;
    }

    /**
     * Get error value
     * @return string
     */
    public function getError()
    {
        return $this->_error;
    }

}