package com.niraj.securitydemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.datasource.init.DataSourceInitializer;

import javax.sql.DataSource;

//@Configuration
public class DataSourceConfig {

    @Autowired
    private DataSource dataSource;
    @Bean
    public DataSourceInitializer dataSourceInitializer(){
        DataSourceInitializer initializer = new DataSourceInitializer();
        //initializer.setDataSource(dataSource);

       // ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
        //populator.addScript(new ClassPathResource("schema.sql")); // Adjust the path to your SQL script
        //initializer.setDatabasePopulator(populator);
        return initializer;


    }
}
