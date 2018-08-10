<?php 

use Doctrine\DBAL\Connection;
use Oc\Repository\Exception\RecordAlreadyExistsException;
use Oc\Repository\Exception\RecordNotFoundException;
use Oc\Repository\Exception\RecordNotPersistedException;
use Oc\Repository\Exception\RecordsNotFoundException;

class LogTypesRepository
{
    const TABLE = 'log_types';

    /** @var Connection */
    private $connection;

    public function __construct(Connection $connection)
    {
        $this->connection = $connection;
    }

    /**
     * @return LogTypesEntity[]
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
     * @return LogTypesEntity
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
     * @return LogTypesEntity[]
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
     * @param LogTypesEntity $entity
     * @return LogTypesEntity
     */
    public function create(LogTypesEntity $entity)
    {
        if (!$entity->isNew()) {
            throw new RecordAlreadyExistsException('The entity does already exist.');
        }

        $databaseArray = $this->getDatabaseArrayFromEntity($entity);

        $this->connection->insert(
                    self::TABLE,
                    $databaseArray
                );

        $entity->id = (int) $this->connection->lastInsertId();

        return $entity;
    }

    /**
     * @param LogTypesEntity $entity
     * @return LogTypesEntity
     */
    public function update(LogTypesEntity $entity)
    {
        if ($entity->isNew()) {
            throw new RecordNotPersistedException('The entity does not exist.');
        }

        $databaseArray = $this->getDatabaseArrayFromEntity($entity);

        $this->connection->update(
                    self::TABLE,
                    $databaseArray,
                    ['id' => $entity->id]
                );

        return $entity;
    }

    /**
     * @param LogTypesEntity $entity
     * @return LogTypesEntity
     */
    public function remove(LogTypesEntity $entity)
    {
        if ($entity->isNew()) {
            throw new RecordNotPersistedException('The entity does not exist.');
        }

        $this->connection->delete(
                    self::TABLE,
                    ['id' => $entity->id]
                );

        $entity->cacheId = null;

        return $entity;
    }

    /**
     * @param LogTypesEntity $entity
     * @return []
     */
    public function getDatabaseArrayFromEntity(LogTypesEntity $entity)
    {
        return [
        'id' => $entity->id,
        'name' => $entity->name,
        'trans_id' => $entity->transId,
        'permission' => $entity->permission,
        'cache_status' => $entity->cacheStatus,
        'de' => $entity->de,
        'en' => $entity->en,
        'icon_small' => $entity->iconSmall,
        'allow_rating' => $entity->allowRating,
        'require_password' => $entity->requirePassword,
        'maintenance_logs' => $entity->maintenanceLogs,
        ];
    }

    /**
     * @param array $data
     * @return LogTypesEntity
     */
    public function getEntityFromDatabaseArray(array $data)
    {
        $entity = new LogTypesEntity();
        $entity->id = $data['id'];
        $entity->name = $data['name'];
        $entity->transId = $data['trans_id'];
        $entity->permission = $data['permission'];
        $entity->cacheStatus = $data['cache_status'];
        $entity->de = $data['de'];
        $entity->en = $data['en'];
        $entity->iconSmall = $data['icon_small'];
        $entity->allowRating = $data['allow_rating'];
        $entity->requirePassword = $data['require_password'];
        $entity->maintenanceLogs = $data['maintenance_logs'];

        return $entity;
    }
}
