<?php 

use Doctrine\DBAL\Connection;
use Oc\Repository\Exception\RecordAlreadyExistsException;
use Oc\Repository\Exception\RecordNotFoundException;
use Oc\Repository\Exception\RecordNotPersistedException;
use Oc\Repository\Exception\RecordsNotFoundException;

class GeodbIntdataRepository
{
    const TABLE = 'geodb_intdata';

    /** @var Connection */
    private $connection;

    public function __construct(Connection $connection)
    {
        $this->connection = $connection;
    }

    /**
     * @return GeodbIntdataEntity[]
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
     * @return GeodbIntdataEntity
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
     * @return GeodbIntdataEntity[]
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
     * @param GeodbIntdataEntity $entity
     * @return GeodbIntdataEntity
     */
    public function create(GeodbIntdataEntity $entity)
    {
        if (!$entity->isNew()) {
            throw new RecordAlreadyExistsException('The entity does already exist.');
        }

        $databaseArray = $this->getDatabaseArrayFromEntity($entity);

        $this->connection->insert(
                    self::TABLE,
                    $databaseArray
                );

        $entity->locId = (int) $this->connection->lastInsertId();

        return $entity;
    }

    /**
     * @param GeodbIntdataEntity $entity
     * @return GeodbIntdataEntity
     */
    public function update(GeodbIntdataEntity $entity)
    {
        if ($entity->isNew()) {
            throw new RecordNotPersistedException('The entity does not exist.');
        }

        $databaseArray = $this->getDatabaseArrayFromEntity($entity);

        $this->connection->update(
                    self::TABLE,
                    $databaseArray,
                    ['loc_id' => $entity->locId]
                );

        return $entity;
    }

    /**
     * @param GeodbIntdataEntity $entity
     * @return GeodbIntdataEntity
     */
    public function remove(GeodbIntdataEntity $entity)
    {
        if ($entity->isNew()) {
            throw new RecordNotPersistedException('The entity does not exist.');
        }

        $this->connection->delete(
                    self::TABLE,
                    ['loc_id' => $entity->locId]
                );

        $entity->cacheId = null;

        return $entity;
    }

    /**
     * @param GeodbIntdataEntity $entity
     * @return []
     */
    public function getDatabaseArrayFromEntity(GeodbIntdataEntity $entity)
    {
        return [
        'loc_id' => $entity->locId,
        'int_val' => $entity->intVal,
        'int_type' => $entity->intType,
        'int_subtype' => $entity->intSubtype,
        'valid_since' => $entity->validSince,
        'date_type_since' => $entity->dateTypeSince,
        'valid_until' => $entity->validUntil,
        'date_type_until' => $entity->dateTypeUntil,
        ];
    }

    /**
     * @param array $data
     * @return GeodbIntdataEntity
     */
    public function getEntityFromDatabaseArray(array $data)
    {
        $entity = new GeodbIntdataEntity();
        $entity->locId = $data['loc_id'];
        $entity->intVal = $data['int_val'];
        $entity->intType = $data['int_type'];
        $entity->intSubtype = $data['int_subtype'];
        $entity->validSince = $data['valid_since'];
        $entity->dateTypeSince = $data['date_type_since'];
        $entity->validUntil = $data['valid_until'];
        $entity->dateTypeUntil = $data['date_type_until'];

        return $entity;
    }
}
