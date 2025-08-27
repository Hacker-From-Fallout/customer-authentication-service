package com.marketplace.authentication;

import liquibase.Liquibase;
import liquibase.database.Database;
import liquibase.database.DatabaseFactory;
import liquibase.resource.ClassLoaderResourceAccessor;

public class LiquibaseResetChecksums {
    public static void main(String[] args) throws Exception {
        Database database = DatabaseFactory.getInstance()
            .openDatabase("jdbc:postgresql://localhost:5432/customer_authentication_db", "root", "password", null, null);

        Liquibase liquibase = new Liquibase("db/changelog/db.changelog-master.yaml", new ClassLoaderResourceAccessor(), database);
        
        liquibase.clearCheckSums();
        
        database.close();
    }
}
