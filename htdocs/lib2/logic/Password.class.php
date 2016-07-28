<?php

/***************************************************************************
 *  For license information see doc/license.txt
 *
 *  Cryptographic functions for hash, verify or test passwords.
 *
 *  Unicode Reminder メモ
 ***************************************************************************/
class Password
{
    /**
     * Creates a password hash.
     *
     * @param String $password Unmodified password
     *
     * @return bool|string Returns the hashed password, or FALSE on failure.
     */
    public static function hash($password)
    {
        return password_hash($password, self::algo(), self::options());
    }

    /**
     * Checks if the given password matches the given hash.
     *
     * @param String $passwordToTest Unmodified password
     * @param String $hashedPassword A hash created by password_hash(). String contains password, salt, method, cost.
     *
     * @return bool Returns TRUE if the password and hash match, or FALSE otherwise.
     */
    public static function verify($passwordToTest, $hashedPassword)
    {
        return password_verify($passwordToTest, $hashedPassword);
    }

    /**
     * Checks if the given hash matches the given options.
     *
     * @param String $password Unmodified password
     *
     * @return bool Returns TRUE if the hash should be rehashed to match the given algorithm and options, or FALSE otherwise.
     */
    public static function needs_rehash($password)
    {
        return password_needs_rehash($password, self::algo(), self::options());
    }

    /**
     * Returns hashing algorithm for passwords
     *
     * @link http://www.php.net/manual/en/password.constants.php
     * @return int Value of constant from see link
     */
    protected static function algo()
    {
        global $opt;
        if (!empty($opt['logic']['password_hash_algo'])) {
            return $opt['logic']['password_hash_algo'];
        }
        return PASSWORD_DEFAULT;
    }

    /**
     * Returns optional adjustable hashing cost option for php standard password_hash_X functions
     *
     * @return array|null Options for password_hash_X functions
     */
    protected static function options()
    {
        global $opt;
        if (!empty($opt['logic']['password_hash_cost'])
            && is_int($opt['logic']['password_hash_cost'])
            && $opt['logic']['password_hash_cost'] > 0
        ) {
            return array("cost" => $opt['logic']['password_hash_cost']);
        }
        return null;
    }
}