<?php

namespace SilverStripe\BehatExtension\Controllers;

use InvalidArgumentException;
use SilverStripe\Core\Manifest\Module;
use SilverStripe\Core\Manifest\ModuleLoader;

trait ModuleCommandTrait
{
    /**
     * Find target module being tested
     *
     * @param string $name
     * @param bool $error Throw error if not found
     * @return Module
     */
    protected function getModule($name, $error = true)
    {
        if (strpos($name, '@') === 0) {
            $name = substr($name, 1);
        }
        $module = ModuleLoader::inst()->getManifest()->getModule($name);
        if (!$module && $error) {
            throw new InvalidArgumentException("No module $name installed");
        }
        return $module;
    }
}
