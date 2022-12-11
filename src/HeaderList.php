<?php

namespace HttpSignatures;

class HeaderList
{
    /** @var array */
    public $names;

    /** @var bool */
    private $headerListSpecified;

    public function __construct(array $names, $headerListSpecified = true)
    {
        if (!$names) {
            $names = ['date'];
            $this->headerListSpecified = false;
        } else {
            $this->names = array_map(
                [$this, 'normalize'],
                $names
            );
            $this->headerListSpecified = $headerListSpecified;
        }
    }

    /**
     * @return HeaderList
     */
    public static function fromString($string)
    {
        return new static(explode(' ', $string));
    }

    /**
     * @return string
     */
    public function string()
    {
        return implode(' ', $this->names);
    }

    /**
     * @return bool
     */
    public function headerListSpecified()
    {
        return $this->headerListSpecified;
    }

    /**
     * @return string
     */
    private function normalize($name)
    {
        return strtolower($name);
    }
}
