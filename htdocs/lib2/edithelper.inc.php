<?php
/****************************************************************************
 * common functions for text editors
 *
 ****************************************************************************/

// used in both lib1 and lib2 code

require_once __DIR__ . '/smiley.inc.php';


/**
 * Do all the conversions needed to process HTML or plain text editor input,
 * for either storing it into the database or (when swiching modes)
 * re-displaying it in another editor mode.
 *
 * oldDescMode is the mode in which the editor was running which output the $text,
 * or 0 if the text came from the database with `htm_text` = 0.
 *
 * descMode    is == descMode if the user hit the editor's "save" button,
 * or the new mode if the user hit another mode button
 * @param mixed $oldDescMode
 * @param mixed $descMode
 * @param mixed $text
 * @param & $representText
 */

/**
 * @param $oldDescMode
 * @param $descMode
 * @param $text
 * @return mixed|string
 */
function processEditorInput($oldDescMode, $descMode, $text, &$representText)
{
    global $opt, $smiley;

    if ($descMode != 1) {
        if ($oldDescMode == 1) {
            // mode switch from plain text to HTML editor => convert HTML special chars
            $text = nl2br(htmlspecialchars($text));
            // .. and smilies
            $text = ' ' . $text . ' ';   // see Redmine #1103
            $text = str_replace($smiley['text'], $smiley['spaced_image'], $text);
            if (substr($text, 0, 1) == ' ') {
                $text = substr($text, 1);
            }
            if (substr($text, -1) == ' ') {
                $text = substr($text, 0, strlen($text) - 1);
            }
            $representText = $text;
        } else {
            // save HTML input => verify / tidy / filter;
            // also implemented in okapi/services/logs/submit.php
            $purifier = new OcHTMLPurifier($opt);
            $text = $purifier->purify($text);
            $representText = $text;
        }
    } else {
        if ($oldDescMode == 1) {
            // keep plain text for re-presenting to the user
            $representText = $text;
            // convert to HTML for storing to database
            // also implemented in okapi/services/logs/submit.php
            $text = nl2br(htmlspecialchars($text, ENT_COMPAT, 'UTF-8'));
            $text = str_replace('  ', '&nbsp; ', $text);   // can produce new '  ' ('&nbsp; ' + ' ')
            $text = str_replace('  ', '&nbsp; ', $text);
        } else {
            // mode switch from HTML editor to plain text, or decode HTML-encoded plain text
            $representText = html2plaintext($text, $oldDescMode = 0, 0);
        }
    }

    return $text;
}


// $texthtml0 is set if the text is from cache_desc.desc or cache_logs.text
// and text_html is 0, i.e. the text was edited in the "text" editor mode.
//
// If $wrap is > 0, longer lines will be wrapped to new lines.

/**
 * @param $text
 * @param $texthtml0
 * @param $wrap
 *
 * @return mixed|string
 */
function html2plaintext($text, $texthtml0, $wrap)
{
    global $opt, $smiley;

    if ($texthtml0) {
        $text = str_replace(
            [
                '<p>',
                "\n",
                "\r",
            ],
            '',
            $text
        );
        $text = str_replace(
            [
                '<br />',
                '</p>',
            ],
            "\n",
            $text
        );
        $text = html_entity_decode($text, ENT_COMPAT, 'UTF-8');
    } else {
        // convert smileys ...
        $countSmileyImage = count($smiley['image']);
        for ($n = 0; $n < $countSmileyImage; $n++) {
            $text = mb_ereg_replace(
                '<img [^>]*?src=[^>]+?' . str_replace('.', '\.', $smiley['file'][$n]) . '[^>]+?>',
                '[s![' . $smiley['text'][$n] . ']!s]',
                $text
            );
            // the [s[ ]s] is needed to protect the spaces around the smileys
        }

        $h2t = new html2text($text);
        $h2t->set_base_url($opt['page']['default_absolute_url']);
        $h2t->width = $wrap;
        $text = $h2t->get_text();

        $text = str_replace(
            [
                '[s![',
                ']!s]',
            ],
            '',
            $text
        );

        // remove e.g. trailing \n created from </p> by html2text
        while (substr($text, - 2) == "\n\n") {
            $text = substr($text, 0, strlen($text) - 1);
        }
    }

    return $text;
}


/**
 * @return string
 */
function editorJsPath()
{
    return 'resource2/ocstyle/js/editor.js?ft=' . filemtime('resource2/ocstyle/js/editor.js');
}
