<?php
namespace ADmad\JwtAuth\Exception;

use Cake\Network\Exception\UnauthorizedException;

class JwtException extends UnauthorizedException
{

    /**
     * @var string Identifies the error
     */
    protected $_error;

    /**
     * JwtException constructor.
     * @param null $message Exception message
     * @param string $error Error indication
     * @param int $code HTTP code
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
