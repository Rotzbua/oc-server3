<?php

namespace OcDev\KitchenSink\DataProvider;

use BestIt\KitchensinkBundle\DataProviderInterface;
use Symfony\Component\HttpFoundation\Session\Session;

/**
 * Class KitchenSinkDataProvider
 */
class KitchenSinkDataProvider implements DataProviderInterface
{
    /**
     * @var Session
     */
    private $session;

    /**
     * KitchenSinkDataProvider constructor.
     */
    public function __construct(Session $session)
    {
        $this->session = $session;
    }

    /**
     * Returns an array with template vars (and optional their getters) to fill the kitchensink template.
     */
    public function getTemplateVars(): array
    {
        $this->session->getFlashBag()->add('success', 'Erfolgreiche Meldung 1!');
        $this->session->getFlashBag()->add('success', 'Erfolgreiche Meldung 2!');
        $this->session->getFlashBag()->add('info', 'Informative Meldung!');
        $this->session->getFlashBag()->add('error', 'Fehlerhafte Meldung!');

        return [
            'navigation' => 'getNavigationDummies',
        ];
    }

    /**
     * @return string[]
     */
    public function getNavigationDummies()
    {
        return [
            'Home',
            'Home1',
            'Home2',
            'Home3',
        ];
    }
}
