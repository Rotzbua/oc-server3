<?php 

use Doctrine\DBAL\Connection;
use Oc\Repository\Exception\RecordAlreadyExistsException;
use Oc\Repository\Exception\RecordNotFoundException;
use Oc\Repository\Exception\RecordNotPersistedException;
use Oc\Repository\Exception\RecordsNotFoundException;

class OkapiAuthorizationsRepository
{
    const TABLE = 'okapi_authorizations';

    /** @var Connection */
    private $connection;

    public function __construct(Connection $connection)
    {
        $this->connection = $connection;
    }

    /**
     * @return OkapiAuthorizationsEntity[]
     */
    public function fetchAll()
    {
        $statement = $this->connection->createQueryBuilder()
                    ->select('*')
                    ->from(self::TABLE)
                    ->execute();

        $result = $statement->fetchAll();

        if ($statement->rowCount() === 0) {
            throw new RecordsNotFoundException('No records found');
        }

        $records = [];

        foreach ($result as $item) {
            $records[] = $this->getEntityFromDatabaseArray($item);
        }

        return $records;
    }

    /**
     * @param array $where
     * @return OkapiAuthorizationsEntity
     */
    public function fetchOneBy(array $where = [])
    {
        $queryBuilder = $this->connection->createQueryBuilder()
                     ->select('*')
                     ->from(self::TABLE)
                     ->setMaxResults(1);

        if (count($where) > 0) {
            foreach ($where as $column => $value) {
                $queryBuilder->andWhere($column . ' = ' . $queryBuilder->createNamedParameter($value));
            }
        }

        $statement = $queryBuilder->execute();

        $result = $statement->fetch();

        if ($statement->rowCount() === 0) {
            throw new RecordNotFoundException('Record with given where clause not found');
        }

        return $this->getEntityFromDatabaseArray($result);
    }

    /**
     * @param array $where
     * @return OkapiAuthorizationsEntity[]
     */
    public function fetchBy(array $where = [])
    {
        $queryBuilder = $this->connection->createQueryBuilder()
                     ->select('*')
                     ->from(self::TABLE);

        if (count($where) > 0) {
            foreach ($where as $column => $value) {
                $queryBuilder->andWhere($column . ' = ' . $queryBuilder->createNamedParameter($value));
            }
        }

        $statement = $queryBuilder->execute();

        $result = $statement->fetchAll();

        if ($statement->rowCount() === 0) {
            throw new RecordsNotFoundException('No records with given where clause found');
        }

        $entities = [];

        foreach ($result as $item) {
            $entities[] = $this->getEntityFromDatabaseArray($item);
        }

        return $entities;
    }

    /**
     * @param OkapiAuthorizationsEntity $entity
     * @return OkapiAuthorizationsEntity
     */
    public function create(OkapiAuthorizationsEntity $entity)
    {
        if (!$entity->isNew()) {
            throw new RecordAlreadyExistsException('The entity does already exist.');
        }

        $databaseArray = $this->getDatabaseArrayFromEntity($entity);

        $this->connection->insert(
                    self::TABLE,
                    $databaseArray
                );

        $entity->consumerKey = (int) $this->connection->lastInsertId();

        return $entity;
    }

    /**
     * @param OkapiAuthorizationsEntity $entity
     * @return OkapiAuthorizationsEntity
     */
    public function update(OkapiAuthorizationsEntity $entity)
    {
        if ($entity->isNew()) {
            throw new RecordNotPersistedException('The entity does not exist.');
        }

        $databaseArray = $this->getDatabaseArrayFromEntity($entity);

        $this->connection->update(
                    self::TABLE,
                    $databaseArray,
                    ['consumer_key' => $entity->consumerKey]
                );

        return $entity;
    }

    /**
     * @param OkapiAuthorizationsEntity $entity
     * @return OkapiAuthorizationsEntity
     */
    public function remove(OkapiAuthorizationsEntity $entity)
    {
        if ($entity->isNew()) {
            throw new RecordNotPersistedException('The entity does not exist.');
        }

        $this->connection->delete(
                    self::TABLE,
                    ['consumer_key' => $entity->consumerKey]
                );

        $entity->cacheId = null;

        return $entity;
    }

    /**
     * @param OkapiAuthorizationsEntity $entity
     * @return []
     */
    public function getDatabaseArrayFromEntity(OkapiAuthorizationsEntity $entity)
    {
        return [
        'consumer_key' => $entity->consumerKey,
        'user_id' => $entity->userId,
        'last_access_token' => $entity->lastAccessToken,
        ];
    }

    /**
     * @param array $data
     * @return OkapiAuthorizationsEntity
     */
    public function getEntityFromDatabaseArray(array $data)
    {
        $entity = new OkapiAuthorizationsEntity();
        $entity->consumerKey = $data['consumer_key'];
        $entity->userId = $data['user_id'];
        $entity->lastAccessToken = $data['last_access_token'];

        return $entity;
    }
}
