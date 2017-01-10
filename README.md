# SpringMVCHibernateWithSpringSecurityExampl
源码解析及地址：http://websystique.com/springmvc/spring-mvc-4-and-spring-security-4-integration-example/
初始导入sql：init.sql
用户名：sam
密码：abc125

Search for: 
SKIP TO CONTENT
HOME
SPRING BOOT
ANGULARJS
SPRING 4
SPRING 4 MVC
SPRING SECURITY 4
SPRING BATCH
HIBERNATE 4
DIVERS
CONTACT US
WebSystique
learn together
Spring MVC 4 + Spring Security 4 + Hibernate Example
Created on: 2017 | Last updated on: 2017  websystiqueadmin

 
In this post, we will build a full-blown Spring MVC application secured using Spring Security, integrating with MySQL database using Hibernate, handling Many-to-Many relationship on view, storing passwords in encrypted format using BCrypt, and providing RememberMe functionality using custom PersistentTokenRepository implementation with Hibernate HibernateTokenRepositoryImpl, retrieving the records from database and updating or deleting them within transaction, all using annotation configuration.

This project can be served as a template for your own Spring MVC projects integrating Spring Security.

SpringMVCSecurity-img04

SpringMVCSecurity-img12

Note:


 
This post demonstrates a complete application with complete code. In order to manage the size of the post, i have skipped the textual descriptions of some basic stuff. In case you are interested in those details, this ,this & this post will help you.

Summary:

The project shows a simple user-management application. One can create a new user, edit or delete an existing user, and list all the users. User can be associated with one or more UserProfile, showing many-to-many relationship. URL’s of the applications are secured using Spring Security. That means, based on the roles of logged in user, access to certain URL’s will be granted or prohibited. On the view layer, user will see only the content he/she is allowed to based on the roles assigned to him/her, thanks to Spring Security tags for view layer.

Other interesting posts you may like
Spring Boot+AngularJS+Spring Data+Hibernate+MySQL CRUD App
Spring Boot REST API Tutorial
Spring Boot WAR deployment example
Spring Boot Introduction + Hello World Example
Secure Spring REST API using OAuth2
AngularJS+Spring Security using Basic Authentication
Secure Spring REST API using Basic Authentication
Spring 4 Caching Annotations Tutorial
Spring 4 Cache Tutorial with EhCache
Spring 4 Email Template Library Example
Spring 4 MVC+JPA2+Hibernate Many-to-many Example
Spring 4 Email With Attachment Tutorial
Spring 4 Email Integration Tutorial
Spring MVC 4+JMS+ActiveMQ Integration Example
Spring 4+JMS+ActiveMQ @JmsLister @EnableJms Example
Spring 4+JMS+ActiveMQ Integration Example
Spring MVC 4+Apache Tiles 3 Integration Example
Spring MVC 4+AngularJS Example
Spring MVC 4+AngularJS Server communication example : CRUD application using ngResource $resource service
Spring MVC 4+AngularJS Routing with UI-Router Example
Spring MVC 4+Hibernate 4 Many-to-many JSP Example
Spring MVC 4+Hibernate 4+MySQL+Maven integration + Testing example using annotations
Spring Security 4 Hibernate Integration Annotation+XML Example
Spring MVC4 FileUpload-Download Hibernate+MySQL Example
Spring MVC 4 Form Validation and Resource Handling
Spring Batch- MultiResourceItemReader & HibernateItemWriter example
Following technologies being used:

Spring 4.2.5.RELEASE
Spring Security 4.0.4.RELEASE
Hibernate Core 4.3.11.Final
validation-api 1.1.0.Final
hibernate-validator 5.1.3.Final
MySQL Server 5.6
Maven 3
JDK 1.7
Tomcat 8.0.21
Eclipse MARS.1 Release 4.5.1
logback 1.1.7
Let’s begin.


 
Step 1: Create the directory structure

Following will be the final project structure:
SpringMVCSecurity-img01SpringMVCSecurity-img02

Let’s now add the content mentioned in above structure explaining each in detail.

Step 2: Update pom.xml to include required dependencies

<project xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd"
    xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.websystique.springmvc</groupId>
    <artifactId>SpringMVCHibernateManyToManyCRUDExample</artifactId>
    <packaging>war</packaging>
    <version>1.0.0</version>
    <name>SpringMVCHibernateWithSpringSecurityExample</name>
 
    <properties>
        <springframework.version>4.2.5.RELEASE</springframework.version>
        <springsecurity.version>4.0.4.RELEASE</springsecurity.version>
        <hibernate.version>4.3.11.Final</hibernate.version>
        <mysql.connector.version>5.1.31</mysql.connector.version>
    </properties>
 
    <dependencies>
        <!-- Spring -->
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>${springframework.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-web</artifactId>
            <version>${springframework.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-webmvc</artifactId>
            <version>${springframework.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-tx</artifactId>
            <version>${springframework.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-orm</artifactId>
            <version>${springframework.version}</version>
        </dependency>
 
        <!-- Spring Security -->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-web</artifactId>
            <version>${springsecurity.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-config</artifactId>
            <version>${springsecurity.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-taglibs</artifactId>
            <version>${springsecurity.version}</version>
        </dependency>
 
 
        <!-- Hibernate -->
        <dependency>
            <groupId>org.hibernate</groupId>
            <artifactId>hibernate-core</artifactId>
            <version>${hibernate.version}</version>
        </dependency>
 
        <!-- jsr303 validation -->
        <dependency>
            <groupId>javax.validation</groupId>
            <artifactId>validation-api</artifactId>
            <version>1.1.0.Final</version>
        </dependency>
        <dependency>
            <groupId>org.hibernate</groupId>
            <artifactId>hibernate-validator</artifactId>
            <version>5.1.3.Final</version>
        </dependency>
         
        <!-- MySQL -->
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>${mysql.connector.version}</version>
        </dependency>
         
        <!-- SLF4J/Logback -->
        <dependency>
            <groupId>ch.qos.logback</groupId>
            <artifactId>logback-classic</artifactId>
            <version>1.1.7</version>
        </dependency>
 
        <!-- Servlet+JSP+JSTL -->
        <dependency>
            <groupId>javax.servlet</groupId>
            <artifactId>javax.servlet-api</artifactId>
            <version>3.1.0</version>
        </dependency>
        <dependency>
            <groupId>javax.servlet.jsp</groupId>
            <artifactId>javax.servlet.jsp-api</artifactId>
            <version>2.3.1</version>
        </dependency>
        <dependency>
            <groupId>javax.servlet</groupId>
            <artifactId>jstl</artifactId>
            <version>1.2</version>
        </dependency>
         
    </dependencies>
 
    <build>
        <pluginManagement>
            <plugins>
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-compiler-plugin</artifactId>
                    <version>3.2</version>
                    <configuration>
                        <source>1.7</source>
                        <target>1.7</target>
                    </configuration>
                </plugin>
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-war-plugin</artifactId>
                    <version>2.4</version>
                    <configuration>
                        <warSourceDirectory>src/main/webapp</warSourceDirectory>
                        <warName>SpringMVCHibernateWithSpringSecurityExample</warName>
                        <failOnMissingWebXml>false</failOnMissingWebXml>
                    </configuration>
                </plugin>
            </plugins>
        </pluginManagement>
        <finalName>SpringMVCHibernateWithSpringSecurityExample</finalName>
    </build>
</project>
Step 3: Configure Security

The first and foremost step to add spring security in our application is to create Spring Security Java Configuration. This configuration creates a Servlet Filter known as the springSecurityFilterChain which is responsible for all the security (protecting the application URLs, validating submitted username and passwords, redirecting to the log in form, etc) within our application

package com.websystique.springmvc.security;
 
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
 
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
 
    @Autowired
    @Qualifier("customUserDetailsService")
    UserDetailsService userDetailsService;
 
    @Autowired
    PersistentTokenRepository tokenRepository;
 
    @Autowired
    public void configureGlobalSecurity(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
        auth.authenticationProvider(authenticationProvider());
    }
 
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/", "/list")
                .access("hasRole('USER') or hasRole('ADMIN') or hasRole('DBA')")
                .antMatchers("/newuser/**", "/delete-user-*").access("hasRole('ADMIN')").antMatchers("/edit-user-*")
                .access("hasRole('ADMIN') or hasRole('DBA')").and().formLogin().loginPage("/login")
                .loginProcessingUrl("/login").usernameParameter("ssoId").passwordParameter("password").and()
                .rememberMe().rememberMeParameter("remember-me").tokenRepository(tokenRepository)
                .tokenValiditySeconds(86400).and().csrf().and().exceptionHandling().accessDeniedPage("/Access_Denied");
    }
 
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
 
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }
 
    @Bean
    public PersistentTokenBasedRememberMeServices getPersistentTokenBasedRememberMeServices() {
        PersistentTokenBasedRememberMeServices tokenBasedservice = new PersistentTokenBasedRememberMeServices(
                "remember-me", userDetailsService, tokenRepository);
        return tokenBasedservice;
    }
 
    @Bean
    public AuthenticationTrustResolver getAuthenticationTrustResolver() {
        return new AuthenticationTrustResolverImpl();
    }
 
}
As shown above, the access to URLs is governed as follows:

‘/’ & ‘/list’ : Accessible to everyone
‘/newuser’ & ‘/delete-user-*’ : Accessible only to Admin
‘/edit-user-*’ : Accessible to Admin & DBA
Since we are storing the credentials in database, configuring DaoAuthenticationProvider with UserDetailsService would come handy. Additionally, in order to encrypt the password in database, we have chosen BCryptPasswordEncoder. Moreover, since we will also provide RememberMe functionality, keeping track of token-data in database, we configured a PersistentTokenRepository implementation.

Spring Security comes with two implementation of PersistentTokenRepository : JdbcTokenRepositoryImpl and InMemoryTokenRepositoryImpl. We could have opted for JdbcTokenRepositoryImpl [this post demonstrates the RememberMe with JdbcTokenRepositoryImpl], but since we are using Hibernate in our application, why not create a custom implementation using Hibernate instead of using JDBC? Shown below is an attempt for the same.

package com.websystique.springmvc.dao;
 
import java.util.Date;
 
import org.hibernate.Criteria;
import org.hibernate.criterion.Restrictions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
 
import com.websystique.springmvc.dao.AbstractDao;
import com.websystique.springmvc.model.PersistentLogin;
 
@Repository("tokenRepositoryDao")
@Transactional
public class HibernateTokenRepositoryImpl extends AbstractDao<String, PersistentLogin>
        implements PersistentTokenRepository {
 
    static final Logger logger = LoggerFactory.getLogger(HibernateTokenRepositoryImpl.class);
 
    @Override
    public void createNewToken(PersistentRememberMeToken token) {
        logger.info("Creating Token for user : {}", token.getUsername());
        PersistentLogin persistentLogin = new PersistentLogin();
        persistentLogin.setUsername(token.getUsername());
        persistentLogin.setSeries(token.getSeries());
        persistentLogin.setToken(token.getTokenValue());
        persistentLogin.setLast_used(token.getDate());
        persist(persistentLogin);
 
    }
 
    @Override
    public PersistentRememberMeToken getTokenForSeries(String seriesId) {
        logger.info("Fetch Token if any for seriesId : {}", seriesId);
        try {
            Criteria crit = createEntityCriteria();
            crit.add(Restrictions.eq("series", seriesId));
            PersistentLogin persistentLogin = (PersistentLogin) crit.uniqueResult();
 
            return new PersistentRememberMeToken(persistentLogin.getUsername(), persistentLogin.getSeries(),
                    persistentLogin.getToken(), persistentLogin.getLast_used());
        } catch (Exception e) {
            logger.info("Token not found...");
            return null;
        }
    }
 
    @Override
    public void removeUserTokens(String username) {
        logger.info("Removing Token if any for user : {}", username);
        Criteria crit = createEntityCriteria();
        crit.add(Restrictions.eq("username", username));
        PersistentLogin persistentLogin = (PersistentLogin) crit.uniqueResult();
        if (persistentLogin != null) {
            logger.info("rememberMe was selected");
            delete(persistentLogin);
        }
 
    }
 
    @Override
    public void updateToken(String seriesId, String tokenValue, Date lastUsed) {
        logger.info("Updating Token for seriesId : {}", seriesId);
        PersistentLogin persistentLogin = getByKey(seriesId);
        persistentLogin.setToken(tokenValue);
        persistentLogin.setLast_used(lastUsed);
        update(persistentLogin);
    }
 
}
Above implementation uses an Entity [PersistentLogin] mapped to persistent_logins table, shown below is the entity itself.

package com.websystique.springmvc.model;
 
import java.io.Serializable;
import java.util.Date;
 
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
 
@Entity
@Table(name="PERSISTENT_LOGINS")
public class PersistentLogin implements Serializable{
 
    @Id
    private String series;
 
    @Column(name="USERNAME", unique=true, nullable=false)
    private String username;
     
    @Column(name="TOKEN", unique=true, nullable=false)
    private String token;
     
    @Temporal(TemporalType.TIMESTAMP)
    private Date last_used;
 
    public String getSeries() {
        return series;
    }
 
    public void setSeries(String series) {
        this.series = series;
    }
 
    public String getUsername() {
        return username;
    }
 
    public void setUsername(String username) {
        this.username = username;
    }
 
    public String getToken() {
        return token;
    }
 
    public void setToken(String token) {
        this.token = token;
    }
 
    public Date getLast_used() {
        return last_used;
    }
 
    public void setLast_used(Date last_used) {
        this.last_used = last_used;
    }
     
     
}
The UserDetailsService implementation, used in Security configuration is shown below:

package com.websystique.springmvc.security;
 
import java.util.ArrayList;
import java.util.List;
 
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
 
import com.websystique.springmvc.model.User;
import com.websystique.springmvc.model.UserProfile;
import com.websystique.springmvc.service.UserService;
 
 
@Service("customUserDetailsService")
public class CustomUserDetailsService implements UserDetailsService{
 
    static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);
     
    @Autowired
    private UserService userService;
     
    @Transactional(readOnly=true)
    public UserDetails loadUserByUsername(String ssoId)
            throws UsernameNotFoundException {
        User user = userService.findBySSO(ssoId);
        logger.info("User : {}", user);
        if(user==null){
            logger.info("User not found");
            throw new UsernameNotFoundException("Username not found");
        }
            return new org.springframework.security.core.userdetails.User(user.getSsoId(), user.getPassword(), 
                 true, true, true, true, getGrantedAuthorities(user));
    }
 
     
    private List<GrantedAuthority> getGrantedAuthorities(User user){
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
         
        for(UserProfile userProfile : user.getUserProfiles()){
            logger.info("UserProfile : {}", userProfile);
            authorities.add(new SimpleGrantedAuthority("ROLE_"+userProfile.getType()));
        }
        logger.info("authorities : {}", authorities);
        return authorities;
    }
     
}
Finally, register the springSecurityFilter with application war using below mentioned initializer class.

package com.websystique.springmvc.security;
 
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
 
public class SecurityWebApplicationInitializer extends AbstractSecurityWebApplicationInitializer {
 
}
That’s all with Spring Security Configuration. Now let’s begin with Spring MVC part, discussing Hibernate configuration, necessary DAO, models & services along the way.

Step 4: Configure Hibernate

package com.websystique.springmvc.configuration;
 
import java.util.Properties;
 
import javax.sql.DataSource;
 
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.hibernate4.HibernateTransactionManager;
import org.springframework.orm.hibernate4.LocalSessionFactoryBean;
import org.springframework.transaction.annotation.EnableTransactionManagement;
 
@Configuration
@EnableTransactionManagement
@ComponentScan({ "com.websystique.springmvc.configuration" })
@PropertySource(value = { "classpath:application.properties" })
public class HibernateConfiguration {
 
    @Autowired
    private Environment environment;
 
    @Bean
    public LocalSessionFactoryBean sessionFactory() {
        LocalSessionFactoryBean sessionFactory = new LocalSessionFactoryBean();
        sessionFactory.setDataSource(dataSource());
        sessionFactory.setPackagesToScan(new String[] { "com.websystique.springmvc.model" });
        sessionFactory.setHibernateProperties(hibernateProperties());
        return sessionFactory;
     }
     
    @Bean
    public DataSource dataSource() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName(environment.getRequiredProperty("jdbc.driverClassName"));
        dataSource.setUrl(environment.getRequiredProperty("jdbc.url"));
        dataSource.setUsername(environment.getRequiredProperty("jdbc.username"));
        dataSource.setPassword(environment.getRequiredProperty("jdbc.password"));
        return dataSource;
    }
     
    private Properties hibernateProperties() {
        Properties properties = new Properties();
        properties.put("hibernate.dialect", environment.getRequiredProperty("hibernate.dialect"));
        properties.put("hibernate.show_sql", environment.getRequiredProperty("hibernate.show_sql"));
        properties.put("hibernate.format_sql", environment.getRequiredProperty("hibernate.format_sql"));
        return properties;        
    }
     
    @Bean
    @Autowired
    public HibernateTransactionManager transactionManager(SessionFactory s) {
       HibernateTransactionManager txManager = new HibernateTransactionManager();
       txManager.setSessionFactory(s);
       return txManager;
    }
}
Below is the properties file used in this post.
/src/main/resources/application.properties

jdbc.driverClassName = com.mysql.jdbc.Driver
jdbc.url = jdbc:mysql://localhost:3306/websystique
jdbc.username = myuser
jdbc.password = mypassword
hibernate.dialect = org.hibernate.dialect.MySQLDialect
hibernate.show_sql = true
hibernate.format_sql = true
Step 5: Configure Spring MVC

package com.websystique.springmvc.configuration;
 
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewResolverRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.JstlView;
 
import com.websystique.springmvc.converter.RoleToUserProfileConverter;
 
 
@Configuration
@EnableWebMvc
@ComponentScan(basePackages = "com.websystique.springmvc")
public class AppConfig extends WebMvcConfigurerAdapter{
     
     
    @Autowired
    RoleToUserProfileConverter roleToUserProfileConverter;
     
 
    /**
     * Configure ViewResolvers to deliver preferred views.
     */
    @Override
    public void configureViewResolvers(ViewResolverRegistry registry) {
 
        InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
        viewResolver.setViewClass(JstlView.class);
        viewResolver.setPrefix("/WEB-INF/views/");
        viewResolver.setSuffix(".jsp");
        registry.viewResolver(viewResolver);
    }
     
    /**
     * Configure ResourceHandlers to serve static resources like CSS/ Javascript etc...
     */
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/static/**").addResourceLocations("/static/");
    }
     
    /**
     * Configure Converter to be used.
     * In our example, we need a converter to convert string values[Roles] to UserProfiles in newUser.jsp
     */
    @Override
    public void addFormatters(FormatterRegistry registry) {
        registry.addConverter(roleToUserProfileConverter);
    }
     
 
    /**
     * Configure MessageSource to lookup any validation/error message in internationalized property files
     */
    @Bean
    public MessageSource messageSource() {
        ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
        messageSource.setBasename("messages");
        return messageSource;
    }
     
    /**Optional. It's only required when handling '.' in @PathVariables which otherwise ignore everything after last '.' in @PathVaidables argument.
     * It's a known bug in Spring [https://jira.spring.io/browse/SPR-6164], still present in Spring 4.1.7.
     * This is a workaround for this issue.
     */
    @Override
    public void configurePathMatch(PathMatchConfigurer matcher) {
        matcher.setUseRegisteredSuffixPatternMatch(true);
    }
}
The main highlight of this configuration is RoleToUserProfileConverter. It will take care of mapping the individual userProfile id’s on view to actual UserProfile Entities in database.

package com.websystique.springmvc.converter;
 
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;
 
import com.websystique.springmvc.model.UserProfile;
import com.websystique.springmvc.service.UserProfileService;
 
/**
 * A converter class used in views to map id's to actual userProfile objects.
 */
@Component
public class RoleToUserProfileConverter implements Converter<Object, UserProfile>{
 
    static final Logger logger = LoggerFactory.getLogger(RoleToUserProfileConverter.class);
     
    @Autowired
    UserProfileService userProfileService;
 
    /**
     * Gets UserProfile by Id
     * @see org.springframework.core.convert.converter.Converter#convert(java.lang.Object)
     */
    public UserProfile convert(Object element) {
        Integer id = Integer.parseInt((String)element);
        UserProfile profile= userProfileService.findById(id);
        logger.info("Profile : {}",profile);
        return profile;
    }
     
}
Since we are using JSR validators in our application to validate user input, we have configured the messages to be shown to user in case of validation failures. shown below is message.properties file:

NotEmpty.user.firstName=First name can not be blank.
NotEmpty.user.lastName=Last name can not be blank.
NotEmpty.user.email=Email can not be blank.
NotEmpty.user.password=Password can not be blank.
NotEmpty.user.ssoId=SSO ID can not be blank.
NotEmpty.user.userProfiles=At least one profile must be selected.
non.unique.ssoId=SSO ID {0} already exist. Please fill in different value.
Finally, the Spring Intializer class is shown below:

package com.websystique.springmvc.configuration;
 
import org.springframework.web.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer;
 
public class AppInitializer extends AbstractAnnotationConfigDispatcherServletInitializer {
 
    @Override
    protected Class<?>[] getRootConfigClasses() {
        return new Class[] { AppConfig.class };
    }
  
    @Override
    protected Class<?>[] getServletConfigClasses() {
        return null;
    }
  
    @Override
    protected String[] getServletMappings() {
        return new String[] { "/" };
    }
 
}
Step 6: Create Spring Controller

package com.websystique.springmvc.controller;
 
import java.util.List;
import java.util.Locale;
 
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
 
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
 
import com.websystique.springmvc.model.User;
import com.websystique.springmvc.model.UserProfile;
import com.websystique.springmvc.service.UserProfileService;
import com.websystique.springmvc.service.UserService;
 
 
 
@Controller
@RequestMapping("/")
@SessionAttributes("roles")
public class AppController {
 
    @Autowired
    UserService userService;
     
    @Autowired
    UserProfileService userProfileService;
     
    @Autowired
    MessageSource messageSource;
 
    @Autowired
    PersistentTokenBasedRememberMeServices persistentTokenBasedRememberMeServices;
     
    @Autowired
    AuthenticationTrustResolver authenticationTrustResolver;
     
     
    /**
     * This method will list all existing users.
     */
    @RequestMapping(value = { "/", "/list" }, method = RequestMethod.GET)
    public String listUsers(ModelMap model) {
 
        List<User> users = userService.findAllUsers();
        model.addAttribute("users", users);
        model.addAttribute("loggedinuser", getPrincipal());
        return "userslist";
    }
 
    /**
     * This method will provide the medium to add a new user.
     */
    @RequestMapping(value = { "/newuser" }, method = RequestMethod.GET)
    public String newUser(ModelMap model) {
        User user = new User();
        model.addAttribute("user", user);
        model.addAttribute("edit", false);
        model.addAttribute("loggedinuser", getPrincipal());
        return "registration";
    }
 
    /**
     * This method will be called on form submission, handling POST request for
     * saving user in database. It also validates the user input
     */
    @RequestMapping(value = { "/newuser" }, method = RequestMethod.POST)
    public String saveUser(@Valid User user, BindingResult result,
            ModelMap model) {
 
        if (result.hasErrors()) {
            return "registration";
        }
 
        /*
         * Preferred way to achieve uniqueness of field [sso] should be implementing custom @Unique annotation 
         * and applying it on field [sso] of Model class [User].
         * 
         * Below mentioned peace of code [if block] is to demonstrate that you can fill custom errors outside the validation
         * framework as well while still using internationalized messages.
         * 
         */
        if(!userService.isUserSSOUnique(user.getId(), user.getSsoId())){
            FieldError ssoError =new FieldError("user","ssoId",messageSource.getMessage("non.unique.ssoId", new String[]{user.getSsoId()}, Locale.getDefault()));
            result.addError(ssoError);
            return "registration";
        }
         
        userService.saveUser(user);
 
        model.addAttribute("success", "User " + user.getFirstName() + " "+ user.getLastName() + " registered successfully");
        model.addAttribute("loggedinuser", getPrincipal());
        //return "success";
        return "registrationsuccess";
    }
 
 
    /**
     * This method will provide the medium to update an existing user.
     */
    @RequestMapping(value = { "/edit-user-{ssoId}" }, method = RequestMethod.GET)
    public String editUser(@PathVariable String ssoId, ModelMap model) {
        User user = userService.findBySSO(ssoId);
        model.addAttribute("user", user);
        model.addAttribute("edit", true);
        model.addAttribute("loggedinuser", getPrincipal());
        return "registration";
    }
     
    /**
     * This method will be called on form submission, handling POST request for
     * updating user in database. It also validates the user input
     */
    @RequestMapping(value = { "/edit-user-{ssoId}" }, method = RequestMethod.POST)
    public String updateUser(@Valid User user, BindingResult result,
            ModelMap model, @PathVariable String ssoId) {
 
        if (result.hasErrors()) {
            return "registration";
        }
 
        /*//Uncomment below 'if block' if you WANT TO ALLOW UPDATING SSO_ID in UI which is a unique key to a User.
        if(!userService.isUserSSOUnique(user.getId(), user.getSsoId())){
            FieldError ssoError =new FieldError("user","ssoId",messageSource.getMessage("non.unique.ssoId", new String[]{user.getSsoId()}, Locale.getDefault()));
            result.addError(ssoError);
            return "registration";
        }*/
 
 
        userService.updateUser(user);
 
        model.addAttribute("success", "User " + user.getFirstName() + " "+ user.getLastName() + " updated successfully");
        model.addAttribute("loggedinuser", getPrincipal());
        return "registrationsuccess";
    }
 
     
    /**
     * This method will delete an user by it's SSOID value.
     */
    @RequestMapping(value = { "/delete-user-{ssoId}" }, method = RequestMethod.GET)
    public String deleteUser(@PathVariable String ssoId) {
        userService.deleteUserBySSO(ssoId);
        return "redirect:/list";
    }
     
 
    /**
     * This method will provide UserProfile list to views
     */
    @ModelAttribute("roles")
    public List<UserProfile> initializeProfiles() {
        return userProfileService.findAll();
    }
     
    /**
     * This method handles Access-Denied redirect.
     */
    @RequestMapping(value = "/Access_Denied", method = RequestMethod.GET)
    public String accessDeniedPage(ModelMap model) {
        model.addAttribute("loggedinuser", getPrincipal());
        return "accessDenied";
    }
 
    /**
     * This method handles login GET requests.
     * If users is already logged-in and tries to goto login page again, will be redirected to list page.
     */
    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String loginPage() {
        if (isCurrentAuthenticationAnonymous()) {
            return "login";
        } else {
            return "redirect:/list";  
        }
    }
 
    /**
     * This method handles logout requests.
     * Toggle the handlers if you are RememberMe functionality is useless in your app.
     */
    @RequestMapping(value="/logout", method = RequestMethod.GET)
    public String logoutPage (HttpServletRequest request, HttpServletResponse response){
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null){    
            //new SecurityContextLogoutHandler().logout(request, response, auth);
            persistentTokenBasedRememberMeServices.logout(request, response, auth);
            SecurityContextHolder.getContext().setAuthentication(null);
        }
        return "redirect:/login?logout";
    }
 
    /**
     * This method returns the principal[user-name] of logged-in user.
     */
    private String getPrincipal(){
        String userName = null;
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
 
        if (principal instanceof UserDetails) {
            userName = ((UserDetails)principal).getUsername();
        } else {
            userName = principal.toString();
        }
        return userName;
    }
     
    /**
     * This method returns true if users is already authenticated [logged-in], else false.
     */
    private boolean isCurrentAuthenticationAnonymous() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authenticationTrustResolver.isAnonymous(authentication);
    }
 
 
}
This is a trivial Spring MVC controller. Comments on Each method provide the explanations.


 
Step 7: Create Models

package com.websystique.springmvc.model;
 
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;
 
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
 
import org.hibernate.validator.constraints.NotEmpty;
 
@Entity
@Table(name="APP_USER")
public class User implements Serializable{
 
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY)
    private Integer id;
 
    @NotEmpty
    @Column(name="SSO_ID", unique=true, nullable=false)
    private String ssoId;
     
    @NotEmpty
    @Column(name="PASSWORD", nullable=false)
    private String password;
         
    @NotEmpty
    @Column(name="FIRST_NAME", nullable=false)
    private String firstName;
 
    @NotEmpty
    @Column(name="LAST_NAME", nullable=false)
    private String lastName;
 
    @NotEmpty
    @Column(name="EMAIL", nullable=false)
    private String email;
 
    @NotEmpty
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "APP_USER_USER_PROFILE", 
             joinColumns = { @JoinColumn(name = "USER_ID") }, 
             inverseJoinColumns = { @JoinColumn(name = "USER_PROFILE_ID") })
    private Set<UserProfile> userProfiles = new HashSet<UserProfile>();
 
    public Integer getId() {
        return id;
    }
 
    public void setId(Integer id) {
        this.id = id;
    }
 
    public String getSsoId() {
        return ssoId;
    }
 
    public void setSsoId(String ssoId) {
        this.ssoId = ssoId;
    }
 
    public String getPassword() {
        return password;
    }
 
    public void setPassword(String password) {
        this.password = password;
    }
 
    public String getFirstName() {
        return firstName;
    }
 
    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }
 
    public String getLastName() {
        return lastName;
    }
 
    public void setLastName(String lastName) {
        this.lastName = lastName;
    }
 
    public String getEmail() {
        return email;
    }
 
    public void setEmail(String email) {
        this.email = email;
    }
 
    public Set<UserProfile> getUserProfiles() {
        return userProfiles;
    }
 
    public void setUserProfiles(Set<UserProfile> userProfiles) {
        this.userProfiles = userProfiles;
    }
 
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        result = prime * result + ((ssoId == null) ? 0 : ssoId.hashCode());
        return result;
    }
 
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (!(obj instanceof User))
            return false;
        User other = (User) obj;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        if (ssoId == null) {
            if (other.ssoId != null)
                return false;
        } else if (!ssoId.equals(other.ssoId))
            return false;
        return true;
    }
 
    /*
     * DO-NOT-INCLUDE passwords in toString function.
     * It is done here just for convenience purpose.
     */
    @Override
    public String toString() {
        return "User [id=" + id + ", ssoId=" + ssoId + ", password=" + password
                + ", firstName=" + firstName + ", lastName=" + lastName
                + ", email=" + email + "]";
    }
 
 
     
}
package com.websystique.springmvc.model;
 
import java.io.Serializable;
 
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
 
@Entity
@Table(name="USER_PROFILE")
public class UserProfile implements Serializable{
 
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY)
    private Integer id; 
 
    @Column(name="TYPE", length=15, unique=true, nullable=false)
    private String type = UserProfileType.USER.getUserProfileType();
     
    public Integer getId() {
        return id;
    }
 
    public void setId(Integer id) {
        this.id = id;
    }
 
    public String getType() {
        return type;
    }
 
    public void setType(String type) {
        this.type = type;
    }
 
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        return result;
    }
 
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (!(obj instanceof UserProfile))
            return false;
        UserProfile other = (UserProfile) obj;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        if (type == null) {
            if (other.type != null)
                return false;
        } else if (!type.equals(other.type))
            return false;
        return true;
    }
 
    @Override
    public String toString() {
        return "UserProfile [id=" + id + ", type=" + type + "]";
    }
 
 
 
 
}
package com.websystique.springmvc.model;
 
import java.io.Serializable;
 
public enum UserProfileType implements Serializable{
    USER("USER"),
    DBA("DBA"),
    ADMIN("ADMIN");
     
    String userProfileType;
     
    private UserProfileType(String userProfileType){
        this.userProfileType = userProfileType;
    }
     
    public String getUserProfileType(){
        return userProfileType;
    }
     
}
Step 7: Create DAOs

package com.websystique.springmvc.dao;
 
import java.io.Serializable;
 
import java.lang.reflect.ParameterizedType;
 
import org.hibernate.Criteria;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
 
public abstract class AbstractDao<PK extends Serializable, T> {
     
    private final Class<T> persistentClass;
     
    @SuppressWarnings("unchecked")
    public AbstractDao(){
        this.persistentClass =(Class<T>) ((ParameterizedType) this.getClass().getGenericSuperclass()).getActualTypeArguments()[1];
    }
     
    @Autowired
    private SessionFactory sessionFactory;
 
    protected Session getSession(){
        return sessionFactory.getCurrentSession();
    }
 
    @SuppressWarnings("unchecked")
    public T getByKey(PK key) {
        return (T) getSession().get(persistentClass, key);
    }
 
    public void persist(T entity) {
        getSession().persist(entity);
    }
 
    public void update(T entity) {
        getSession().update(entity);
    }
 
    public void delete(T entity) {
        getSession().delete(entity);
    }
     
    protected Criteria createEntityCriteria(){
        return getSession().createCriteria(persistentClass);
    }
 
}
package com.websystique.springmvc.dao;
 
import java.util.List;
 
import com.websystique.springmvc.model.User;
 
 
public interface UserDao {
 
    User findById(int id);
     
    User findBySSO(String sso);
     
    void save(User user);
     
    void deleteBySSO(String sso);
     
    List<User> findAllUsers();
 
}
package com.websystique.springmvc.dao;
 
import java.util.List;
 
import org.hibernate.Criteria;
import org.hibernate.Hibernate;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;
 
import com.websystique.springmvc.model.User;
 
 
 
@Repository("userDao")
public class UserDaoImpl extends AbstractDao<Integer, User> implements UserDao {
 
    static final Logger logger = LoggerFactory.getLogger(UserDaoImpl.class);
     
    public User findById(int id) {
        User user = getByKey(id);
        if(user!=null){
            Hibernate.initialize(user.getUserProfiles());
        }
        return user;
    }
 
    public User findBySSO(String sso) {
        logger.info("SSO : {}", sso);
        Criteria crit = createEntityCriteria();
        crit.add(Restrictions.eq("ssoId", sso));
        User user = (User)crit.uniqueResult();
        if(user!=null){
            Hibernate.initialize(user.getUserProfiles());
        }
        return user;
    }
 
    @SuppressWarnings("unchecked")
    public List<User> findAllUsers() {
        Criteria criteria = createEntityCriteria().addOrder(Order.asc("firstName"));
        criteria.setResultTransformer(Criteria.DISTINCT_ROOT_ENTITY);//To avoid duplicates.
        List<User> users = (List<User>) criteria.list();
         
        // No need to fetch userProfiles since we are not showing them on list page. Let them lazy load. 
        // Uncomment below lines for eagerly fetching of userProfiles if you want.
        /*
        for(User user : users){
            Hibernate.initialize(user.getUserProfiles());
        }*/
        return users;
    }
 
    public void save(User user) {
        persist(user);
    }
 
    public void deleteBySSO(String sso) {
        Criteria crit = createEntityCriteria();
        crit.add(Restrictions.eq("ssoId", sso));
        User user = (User)crit.uniqueResult();
        delete(user);
    }
 
}
package com.websystique.springmvc.dao;
 
import java.util.List;
 
import com.websystique.springmvc.model.UserProfile;
 
 
public interface UserProfileDao {
 
    List<UserProfile> findAll();
     
    UserProfile findByType(String type);
     
    UserProfile findById(int id);
}
package com.websystique.springmvc.dao;
 
import java.util.List;
 
import org.hibernate.Criteria;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.springframework.stereotype.Repository;
 
import com.websystique.springmvc.model.UserProfile;
 
 
 
@Repository("userProfileDao")
public class UserProfileDaoImpl extends AbstractDao<Integer, UserProfile>implements UserProfileDao{
 
    public UserProfile findById(int id) {
        return getByKey(id);
    }
 
    public UserProfile findByType(String type) {
        Criteria crit = createEntityCriteria();
        crit.add(Restrictions.eq("type", type));
        return (UserProfile) crit.uniqueResult();
    }
     
    @SuppressWarnings("unchecked")
    public List<UserProfile> findAll(){
        Criteria crit = createEntityCriteria();
        crit.addOrder(Order.asc("type"));
        return (List<UserProfile>)crit.list();
    }
     
}
Step 8: Create Services

package com.websystique.springmvc.service;
 
import java.util.List;
 
import com.websystique.springmvc.model.User;
 
 
public interface UserService {
     
    User findById(int id);
     
    User findBySSO(String sso);
     
    void saveUser(User user);
     
    void updateUser(User user);
     
    void deleteUserBySSO(String sso);
 
    List<User> findAllUsers(); 
     
    boolean isUserSSOUnique(Integer id, String sso);
 
}
package com.websystique.springmvc.service;
 
import java.util.List;
 
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
 
import com.websystique.springmvc.dao.UserDao;
import com.websystique.springmvc.model.User;
 
 
@Service("userService")
@Transactional
public class UserServiceImpl implements UserService{
 
    @Autowired
    private UserDao dao;
 
    @Autowired
    private PasswordEncoder passwordEncoder;
     
    public User findById(int id) {
        return dao.findById(id);
    }
 
    public User findBySSO(String sso) {
        User user = dao.findBySSO(sso);
        return user;
    }
 
    public void saveUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        dao.save(user);
    }
 
    /*
     * Since the method is running with Transaction, No need to call hibernate update explicitly.
     * Just fetch the entity from db and update it with proper values within transaction.
     * It will be updated in db once transaction ends. 
     */
    public void updateUser(User user) {
        User entity = dao.findById(user.getId());
        if(entity!=null){
            entity.setSsoId(user.getSsoId());
            if(!user.getPassword().equals(entity.getPassword())){
                entity.setPassword(passwordEncoder.encode(user.getPassword()));
            }
            entity.setFirstName(user.getFirstName());
            entity.setLastName(user.getLastName());
            entity.setEmail(user.getEmail());
            entity.setUserProfiles(user.getUserProfiles());
        }
    }
 
     
    public void deleteUserBySSO(String sso) {
        dao.deleteBySSO(sso);
    }
 
    public List<User> findAllUsers() {
        return dao.findAllUsers();
    }
 
    public boolean isUserSSOUnique(Integer id, String sso) {
        User user = findBySSO(sso);
        return ( user == null || ((id != null) && (user.getId() == id)));
    }
     
}
package com.websystique.springmvc.service;
 
import java.util.List;
 
import com.websystique.springmvc.model.UserProfile;
 
 
public interface UserProfileService {
 
    UserProfile findById(int id);
 
    UserProfile findByType(String type);
     
    List<UserProfile> findAll();
     
}
package com.websystique.springmvc.service;
 
import java.util.List;
 
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
 
import com.websystique.springmvc.dao.UserProfileDao;
import com.websystique.springmvc.model.UserProfile;
 
 
@Service("userProfileService")
@Transactional
public class UserProfileServiceImpl implements UserProfileService{
     
    @Autowired
    UserProfileDao dao;
     
    public UserProfile findById(int id) {
        return dao.findById(id);
    }
 
    public UserProfile findByType(String type){
        return dao.findByType(type);
    }
 
    public List<UserProfile> findAll() {
        return dao.findAll();
    }
}
Step 9: Create Views

Start with login page,asking username & password, and optionally ‘RememberMe’ flag.

WEB-INF/views/login.jsp

<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ page isELIgnored="false" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
        <title>Login page</title>
        <link href="<c:url value='/static/css/bootstrap.css' />"  rel="stylesheet"></link>
        <link href="<c:url value='/static/css/app.css' />" rel="stylesheet"></link>
        <link rel="stylesheet" type="text/css" href="//cdnjs.cloudflare.com/ajax/libs/font-awesome/4.2.0/css/font-awesome.css" />
    </head>
 
    <body>
        <div id="mainWrapper">
            <div class="login-container">
                <div class="login-card">
                    <div class="login-form">
                        <c:url var="loginUrl" value="/login" />
                        <form action="${loginUrl}" method="post" class="form-horizontal">
                            <c:if test="${param.error != null}">
                                <div class="alert alert-danger">
                                    <p>Invalid username and password.</p>
                                </div>
                            </c:if>
                            <c:if test="${param.logout != null}">
                                <div class="alert alert-success">
                                    <p>You have been logged out successfully.</p>
                                </div>
                            </c:if>
                            <div class="input-group input-sm">
                                <label class="input-group-addon" for="username"><i class="fa fa-user"></i></label>
                                <input type="text" class="form-control" id="username" name="ssoId" placeholder="Enter Username" required>
                            </div>
                            <div class="input-group input-sm">
                                <label class="input-group-addon" for="password"><i class="fa fa-lock"></i></label> 
                                <input type="password" class="form-control" id="password" name="password" placeholder="Enter Password" required>
                            </div>
                            <div class="input-group input-sm">
                              <div class="checkbox">
                                <label><input type="checkbox" id="rememberme" name="remember-me"> Remember Me</label>  
                              </div>
                            </div>
                            <input type="hidden" name="${_csrf.parameterName}"  value="${_csrf.token}" />
                                 
                            <div class="form-actions">
                                <input type="submit"
                                    class="btn btn-block btn-primary btn-default" value="Log in">
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
 
    </body>
</html>
Once the user is logged-in successfully, he will be presented with list page, showing all existing users. Pay special attentions to Spring Security tags usage below. Add, Edit & Delete links/buttons are shown based on roles only, so a user with ‘User’ role will not even be able to see them. You may ask: but what about directly typing the url in browser-bar? Well, we have already secured the URL’s in Spring Security configuration, so no-worries.

WEB-INF/views/userslist.jsp

<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ page isELIgnored="false" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags"%>
 
<html>
 
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
    <title>Users List</title>
    <link href="<c:url value='/static/css/bootstrap.css' />" rel="stylesheet"></link>
    <link href="<c:url value='/static/css/app.css' />" rel="stylesheet"></link>
</head>
 
<body>
    <div class="generic-container">
        <%@include file="authheader.jsp" %>   
        <div class="panel panel-default">
              <!-- Default panel contents -->
            <div class="panel-heading"><span class="lead">List of Users </span></div>
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>Firstname</th>
                        <th>Lastname</th>
                        <th>Email</th>
                        <th>SSO ID</th>
                        <sec:authorize access="hasRole('ADMIN') or hasRole('DBA')">
                            <th width="100"></th>
                        </sec:authorize>
                        <sec:authorize access="hasRole('ADMIN')">
                            <th width="100"></th>
                        </sec:authorize>
                         
                    </tr>
                </thead>
                <tbody>
                <c:forEach items="${users}" var="user">
                    <tr>
                        <td>${user.firstName}</td>
                        <td>${user.lastName}</td>
                        <td>${user.email}</td>
                        <td>${user.ssoId}</td>
                        <sec:authorize access="hasRole('ADMIN') or hasRole('DBA')">
                            <td><a href="<c:url value='/edit-user-${user.ssoId}' />" class="btn btn-success custom-width">edit</a></td>
                        </sec:authorize>
                        <sec:authorize access="hasRole('ADMIN')">
                            <td><a href="<c:url value='/delete-user-${user.ssoId}' />" class="btn btn-danger custom-width">delete</a></td>
                        </sec:authorize>
                    </tr>
                </c:forEach>
                </tbody>
            </table>
        </div>
        <sec:authorize access="hasRole('ADMIN')">
            <div class="well">
                <a href="<c:url value='/newuser' />">Add New User</a>
            </div>
        </sec:authorize>
    </div>
</body>
</html>
Above page also includes a jsp containing welcome-messagealong with Logout link as shown below:

WEB-INF/views/authheader.jsp

<div class="authbar">
    <span>Dear <strong>${loggedinuser}</strong>, Welcome to CrazyUsers.</span> <span class="floatRight"><a href="<c:url value="/logout" />">Logout</a></span>
</div>
A user with ‘Admin’ role can add a new user. Shown below is the registration page for the same.
WEB-INF/views/registration.jsp

<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ page isELIgnored="false" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
 
<html>
 
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
    <title>User Registration Form</title>
    <link href="<c:url value='/static/css/bootstrap.css' />" rel="stylesheet"></link>
    <link href="<c:url value='/static/css/app.css' />" rel="stylesheet"></link>
</head>
 
<body>
    <div class="generic-container">
        <%@include file="authheader.jsp" %>
 
        <div class="well lead">User Registration Form</div>
        <form:form method="POST" modelAttribute="user" class="form-horizontal">
            <form:input type="hidden" path="id" id="id"/>
             
            <div class="row">
                <div class="form-group col-md-12">
                    <label class="col-md-3 control-lable" for="firstName">First Name</label>
                    <div class="col-md-7">
                        <form:input type="text" path="firstName" id="firstName" class="form-control input-sm"/>
                        <div class="has-error">
                            <form:errors path="firstName" class="help-inline"/>
                        </div>
                    </div>
                </div>
            </div>
     
            <div class="row">
                <div class="form-group col-md-12">
                    <label class="col-md-3 control-lable" for="lastName">Last Name</label>
                    <div class="col-md-7">
                        <form:input type="text" path="lastName" id="lastName" class="form-control input-sm" />
                        <div class="has-error">
                            <form:errors path="lastName" class="help-inline"/>
                        </div>
                    </div>
                </div>
            </div>
     
            <div class="row">
                <div class="form-group col-md-12">
                    <label class="col-md-3 control-lable" for="ssoId">SSO ID</label>
                    <div class="col-md-7">
                        <c:choose>
                            <c:when test="${edit}">
                                <form:input type="text" path="ssoId" id="ssoId" class="form-control input-sm" disabled="true"/>
                            </c:when>
                            <c:otherwise>
                                <form:input type="text" path="ssoId" id="ssoId" class="form-control input-sm" />
                                <div class="has-error">
                                    <form:errors path="ssoId" class="help-inline"/>
                                </div>
                            </c:otherwise>
                        </c:choose>
                    </div>
                </div>
            </div>
     
            <div class="row">
                <div class="form-group col-md-12">
                    <label class="col-md-3 control-lable" for="password">Password</label>
                    <div class="col-md-7">
                        <form:input type="password" path="password" id="password" class="form-control input-sm" />
                        <div class="has-error">
                            <form:errors path="password" class="help-inline"/>
                        </div>
                    </div>
                </div>
            </div>
     
            <div class="row">
                <div class="form-group col-md-12">
                    <label class="col-md-3 control-lable" for="email">Email</label>
                    <div class="col-md-7">
                        <form:input type="text" path="email" id="email" class="form-control input-sm" />
                        <div class="has-error">
                            <form:errors path="email" class="help-inline"/>
                        </div>
                    </div>
                </div>
            </div>
     
            <div class="row">
                <div class="form-group col-md-12">
                    <label class="col-md-3 control-lable" for="userProfiles">Roles</label>
                    <div class="col-md-7">
                        <form:select path="userProfiles" items="${roles}" multiple="true" itemValue="id" itemLabel="type" class="form-control input-sm" />
                        <div class="has-error">
                            <form:errors path="userProfiles" class="help-inline"/>
                        </div>
                    </div>
                </div>
            </div>
     
            <div class="row">
                <div class="form-actions floatRight">
                    <c:choose>
                        <c:when test="${edit}">
                            <input type="submit" value="Update" class="btn btn-primary btn-sm"/> or <a href="<c:url value='/list' />">Cancel</a>
                        </c:when>
                        <c:otherwise>
                            <input type="submit" value="Register" class="btn btn-primary btn-sm"/> or <a href="<c:url value='/list' />">Cancel</a>
                        </c:otherwise>
                    </c:choose>
                </div>
            </div>
        </form:form>
    </div>
</body>
</html>
WEB-INF/views/registrationsuccess.jsp

<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ page isELIgnored="false" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
 
 
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
    <title>Registration Confirmation Page</title>
    <link href="<c:url value='/static/css/bootstrap.css' />" rel="stylesheet"></link>
    <link href="<c:url value='/static/css/app.css' />" rel="stylesheet"></link>
</head>
<body>
    <div class="generic-container">
        <%@include file="authheader.jsp" %>
         
        <div class="alert alert-success lead">
            ${success}
        </div>
         
        <span class="well floatRight">
            Go to <a href="<c:url value='/list' />">Users List</a>
        </span>
    </div>
</body>
 
</html>
AccessDenied page will be shown if the users is not allowed to go to certain url’s.

WEB-INF/views/accessDenied.jsp

<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ page isELIgnored="false" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
    <title>AccessDenied page</title>
</head>
<body>
    <div class="generic-container">
        <div class="authbar">
            <span>Dear <strong>${loggedinuser}</strong>, You are not authorized to access this page.</span> <span class="floatRight"><a href="<c:url value="/logout" />">Logout</a></span>
        </div>
    </div>
</body>
</html>
Step 10: Create and populate schema in database

/*All User's gets stored in APP_USER table*/
create table APP_USER (
   id BIGINT NOT NULL AUTO_INCREMENT,
   sso_id VARCHAR(30) NOT NULL,
   password VARCHAR(100) NOT NULL,
   first_name VARCHAR(30) NOT NULL,
   last_name  VARCHAR(30) NOT NULL,
   email VARCHAR(30) NOT NULL,
   PRIMARY KEY (id),
   UNIQUE (sso_id)
);
   
/* USER_PROFILE table contains all possible roles */ 
create table USER_PROFILE(
   id BIGINT NOT NULL AUTO_INCREMENT,
   type VARCHAR(30) NOT NULL,
   PRIMARY KEY (id),
   UNIQUE (type)
);
   
/* JOIN TABLE for MANY-TO-MANY relationship*/  
CREATE TABLE APP_USER_USER_PROFILE (
    user_id BIGINT NOT NULL,
    user_profile_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, user_profile_id),
    CONSTRAINT FK_APP_USER FOREIGN KEY (user_id) REFERENCES APP_USER (id),
    CONSTRAINT FK_USER_PROFILE FOREIGN KEY (user_profile_id) REFERENCES USER_PROFILE (id)
);
  
/* Populate USER_PROFILE Table */
INSERT INTO USER_PROFILE(type)
VALUES ('USER');
  
INSERT INTO USER_PROFILE(type)
VALUES ('ADMIN');
  
INSERT INTO USER_PROFILE(type)
VALUES ('DBA');
  
  
/* Populate one Admin User which will further create other users for the application using GUI */
INSERT INTO APP_USER(sso_id, password, first_name, last_name, email)
VALUES ('sam','$2a$10$4eqIF5s/ewJwHK1p8lqlFOEm2QIA0S8g6./Lok.pQxqcxaBZYChRm', 'Sam','Smith','samy@xyz.com');
  
  
/* Populate JOIN Table */
INSERT INTO APP_USER_USER_PROFILE (user_id, user_profile_id)
  SELECT user.id, profile.id FROM app_user user, user_profile profile
  where user.sso_id='sam' and profile.type='ADMIN';
 
/* Create persistent_logins Table used to store rememberme related stuff*/
CREATE TABLE persistent_logins (
    username VARCHAR(64) NOT NULL,
    series VARCHAR(64) NOT NULL,
    token VARCHAR(64) NOT NULL,
    last_used TIMESTAMP NOT NULL,
    PRIMARY KEY (series)
);
Note that we have inserted one user manually(we do need one Admin user to actually login and create further users for application). This is a real-world scenario. Notice the password which is encrypted form of password ‘abc125′. It’s generated using below mentioned utility class [it could even have been a script] which is used only and only to generate a password for one initial Admin user. It can well be removed from application.

package com.websystique.springsecurity.util;
  
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
  
public class QuickPasswordEncodingGenerator {
  
    /**
     * @param args
     */
    public static void main(String[] args) {
            String password = "abc125";
            BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            System.out.println(passwordEncoder.encode(password));
    }
  
}
Step 11: Build, deploy and Run Application

Now build the war (either by eclipse as was mentioned in previous tutorials) or via maven command line( mvn clean install). Deploy the war to a Servlet 3.0 container . Since here i am using Tomcat, i will simply put this war file into tomcat webapps folder and click on start.bat inside tomcat/bin directory.

If you prefer to deploy from within Eclipse using tomcat: For those of us, who prefer to deploy and run from within eclipse, and might be facing difficulties setting Eclipse with tomcat, the detailed step-by-step solution can be found at : How to setup tomcat with Eclipse.

Open browser and browse at http://localhost:8080/SpringMVCHibernateWithSpringSecurityExample/

SpringMVCSecurity-img03

Login with User Sam & password abc125, check RememberMe as well.
SpringMVCSecurity-img04

SpringMVCSecurity-img05

Check database now.An entry should be made in persistent_logins table.
SpringMVCSecurity-img06

Nothing changes for APP_USER table though.
SpringMVCSecurity-img07

Now click on ‘Add new user’ link. Add a user with ‘USER’ role.
SpringMVCSecurity-img08

Click on Register, user should be added.
SpringMVCSecurity-img09

Click on ‘Users List’ link. You should see the newly added user.
SpringMVCSecurity-img10

Add another user with DBA & USER role.
SpringMVCSecurity-img11

Register. Now check the list again.
SpringMVCSecurity-img12

Verify APP_USER table.
SpringMVCSecurity-img13

Now logout.
SpringMVCSecurity-img14

Check persistent_logins table, entry should be removed.
SpringMVCSecurity-img15

Login with user ‘will’ which has ‘User’ role. No Add/Edit/Delete links are available to this user.
SpringMVCSecurity-img16

Now logout and login with ‘bob’. No Add/Delete links are available to this user.
SpringMVCSecurity-img17

Now try to manually type the delete URL in browser-bar and enter.You should see AccessDenied page.
SpringMVCSecurity-img18

That’s it. As we saw, it’s rather simple to integrate Spring Security with Spring MVC. Feel free to Comment, and suggest improvements.

Download Source Code

Download Now!


References

Improved Persistent Login Cookie Best Practice
Spring Security 4 Project Page
Spring Security 4 Reference Manual
Spring 4 Reference Manual

websystiqueadmin
If you like tutorials on this site, why not take a step further and connect me on Facebook , Google Plus & Twitter as well? I would love to hear your thoughts on these articles, it will help me improve further our learning process.
If you appreciate the effort I have put in this learning site, help me improve the visibility of this site towards global audience by sharing and linking this site from within and beyond your network. You & your friends can always link my site from your site on www.websystique.com, and share the learning.

After all, we are here to learn together, aren’t we?

Related Posts:
Spring Security 4 Method security using @PreAuthorize,@PostAuthorize, @Secured, EL
Spring Security 4 Hibernate Role Based Login Example
Spring Security 4 Logout Example
Spring 4 MVC+JPA2+Hibernate Many-to-many-Example
 springmvc.  permalink.
Post navigation
← Spring 4 MVC+AngularJS CRUD Application using ngResourceSpring 4 MVC+Apache Tiles 3 Example →
Jeetendra Garg
Hi,
I want to create roles at run time by the admin and assign permissions to roles as well. Could you please tell that how could I achieve that.
Thanks

Lulú Chaparro Candiani
Hello websystique ..!!
Thanks a lot for the tutorial, this example is great and includes everything i needed for the security part of my project.
I´m trying to add another view and controller to manage “mailing campaigns”. I´ve created the model, DAO, service and controller. When I added the “CampaignController” to the project and deployed it, I get HTTP 404 in http://localhost:8080/SpringMVCHibernateWithSpringSecurityExample/login. If I delete the new controller it works perfectly again.
Is there some file or configuration where i have to add this controller to make it work?.
If I use my “Campaign” CRUD implementation in a separate project it works fine, but when I try to get it together with this Login example it just doesn´t work.
Any idea of what is going on?
Thanks a lot in advance

websystique
Hi, Firstly, adapt SecurityConfiguration.configure method.
@Override
protected void configure(HttpSecurity http) throws Exception {
….
}
Include your new path here to make it accessible/restricted, can add the roles as well. Next, make sure that your your controller is annotated with @Controller and it’s package is covered in component-scanning [along with your new service, DAO etc.]. If you still get issue, i would ask you to paste part of the code here or provide a github link in order to investigate further.

Lulú Chaparro Candiani
Hello,
I solved the problem. I was missing the @Service annotation in the service called by the controller. I added that and everything works great.
Thanks for the reply.

Pingback: Secure Spring REST API using Basic Authentication - WebSystique()

laven
Hello websystique, how to configure this project to UTF-8 ?

websystique
Hi Leven, you can include
UTF-8
inside properties section of pom.xml.

laven
Thank you! I’m use comments from Andrey Gaverdovsky. I’m added this filter to SecurityConfiguration(configure()) and encoding was right:
CharacterEncodingFilter encodingFilter = new CharacterEncodingFilter();
encodingFilter.setEncoding(“UTF-8″);
encodingFilter.setForceEncoding(true);
http.addFilterBefore(encodingFilter, CsrfFilter.class);

Merdiso
Hello websystique. Your tutorial is glorious for a beginner. However, I face two problems with it:

1) I’m using OracleDB instead of MySQL, and while the setup was 100% fine, I have a problem when trying to add a new user. I’ll be as brief as possible.

It seems that your code is trying to insert a new role/userProfile ID into the database when creating a new user, which is wrong, since this “insert” shouldn’t be made, as the roles are already defined before adding other users rather than the original “Admin”, so the DAO should just MAP the new user to the chosen role ID, not add a NEW one into the database. Can you confirm that your implementation shouldn’t behave like that and it could be due to my refactoring, as I changed everything from “userProfile” to “role” within my workspace ?
I tried to pay attention to every single entry but maybe I did something wrong here that could cause this issue.

2) Your UI looks beautiful with that bootstrap lib, but my page looks like there was no bootstrap added whatsoever, but only a bland html page without any layout, icons etc. I can confirm the project structure looks identical to the one in the first step of this tutorial, and I didn’t edit anything in the .jsp files in terms of these .css files references. I’ve also tried both Chrome/Edge browsers but to no avail. Do you know what else could affect this lack of UI bootstrap components on my website ?

Thank you very much for your support anyway, this tutorial is amazing !

websystique
Hello Merdiso, No i don’t add any new userprofiles while adding a new user. For the UI part , please make sure that css is included in your views.If you are following the same approach as in this post, make sure to include JSTL as well. Additionally, could come handy, as it forces expressions to evaluate.

Merdiso
Thank you very much for your reply. For some reason, I added Bootstrap inside a folder “staticS”, I had to pay attention and doublecheck everything to finally notice the additional “s” I typed.
Regarding the “new userprofiles” thing, what solved the trick for me was to set the CascadeType to “Detach” within the User join table relationship in the Model class.

Omkar
Sir,please help me how to change the applcation startup page

websystique
Hi Omkar, for that, you just need to return the new page name from the default controlller-handler.

@RequestMapping(value = { “/”}, method = RequestMethod.GET)
public String homePage(ModelMap model) {
…..
return “MY_NEW_PAGE”;
}

Munarso
I have deployed and running his app in tomcat. But it shows status 404 error. how to fix it ?
https://uploads.disquscdn.com/images/c46f74b50a7b6d627e758e1b41b119366d67c7b1b865f4a82f7caaf48486407a.png

websystique
Hi, Probably related to your local Tomcat setup on Eclipse, please follow the steps to fix that on Setup Tomca With Eclipse ,should be fine.

Munarso
Thank you. Its fix my problem. The solution is i have to add Maven Dependencies in my project.
https://uploads.disquscdn.com/images/e6fe436ede05a3e094813850f496b8287c7d420f1bdd917faf49e57290fbdc7c.png .
Thank you very much for your answers.

qwezxc
Hi websystique, Is it possible for you to do a mongodb version of this?

Feelik
Hello! I need help.
I do as in the example and try to connect PostgreSQL, but see this exception:

java.lang.NullPointerException
ru.safecity58.safecityfull.Controllers.AdminController.listUsers(AdminController.java:38)
sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
java.lang.reflect.Method.invoke(Method.java:498)
org.springframework.web.method.support.InvocableHandlerMethod.doInvoke(InvocableHandlerMethod.java:221)
org.springframework.web.method.support.InvocableHandlerMethod.invokeForRequest(InvocableHandlerMethod.java:136)
org.springframework.web.servlet.mvc.method.annotation.ServletInvocableHandlerMethod.invokeAndHandle(ServletInvocableHandlerMethod.java:114)
org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter.invokeHandlerMethod(RequestMappingHandlerAdapter.java:827)
org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter.handleInternal(RequestMappingHandlerAdapter.java:738)
org.springframework.web.servlet.mvc.method.AbstractHandlerMethodAdapter.handle(AbstractHandlerMethodAdapter.java:85)
org.springframework.web.servlet.DispatcherServlet.doDispatch(DispatcherServlet.java:963)
org.springframework.web.servlet.DispatcherServlet.doService(DispatcherServlet.java:897)
org.springframework.web.servlet.FrameworkServlet.processRequest(FrameworkServlet.java:970)
org.springframework.web.servlet.FrameworkServlet.doGet(FrameworkServlet.java:861)
javax.servlet.http.HttpServlet.service(HttpServlet.java:622)
org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:846)
javax.servlet.http.HttpServlet.service(HttpServlet.java:729)
org.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:52).

websystique
Hi, The exception in above message is referring to

public String listUsers(ModelMap model){
List users = userService.findAllUsers();
model.addAttribute(“users”, users);
return “listusers”;
}

Seems that your userService is not autowired properly. Please make sure that your userService is annotated appropriately and it is in the componant-scan path.

Feelik
Websystique, thank for the answer! I removed @autowired, as because with him usually get a FAIL – Application at context path could not be starte, but if triggered then writes that errors in establishing bean and Autowired=true

websystique
Hi, You have to @Autowire it. The error you get is already an indication that @Autowire was not successful Please check if your class/implementation is covered by component-scanning?

Feelik
https://uploads.disquscdn.com/images/978c3d9e420d5d9000050e0b80b595620c3abedd932e8557bfb9ef0b8305d7fa.jpg

Hi, I returned @Autowire and fixed @ConmponentScan(basePackages = “ru.safecity58.safecityfull”). But … :(

@Configuration
@EnableWebMvc
@EnableTransactionManagement
@ComponentScan(“ru.safecity58.safecityfull.*”)
public class AppConfig extends WebMvcConfigurerAdapter{

…
}

Feelik
https://uploads.disquscdn.com/images/70ba110f603335d9e1b84148dd2ff2faebb92a6dd9549741850e3a0b0d4da8fd.jpg

websystique
Hi, Could you please remove the ‘.*’ from the component scan path? And if you still face the issue, please paste your UserDAO/impl classes.

Feelik
Hi. I rewrote the key processing, but the application no deployed. Building deployed correct

Repository(“usersDao”)
public class UsersDaoImpl extends AbstractDao implements UsersDAO {

static final Logger logger = LoggerFactory.getLogger(UsersDaoImpl.class);
@Autowired
// @Qualifier(“hibernateTemplate”)
// private HibernateTemplate hibernateTemplate;

@Override
public List findAllUsers() {
// List users = new ArrayList();
Criteria criteria = createEntityCriteria().addOrder(Order.asc(“username”));
criteria.setResultTransformer(Criteria.DISTINCT_ROOT_ENTITY);
List users = (List) criteria.list();

return users;
}

@Override
public void addUser(ApplicationUser user) {
persist(user);
}

@Override
public void deleteUser(int id) {
// /*List users = new ArrayList();
// users = hibernateTemplate.getSessionFactory().openSession()
// .createQuery(“from users where id=?”)
/// .setParameter(0, id)
// .list();
// try
// {
// ApplicationUser user = users.get(id);
// hibernateTemplate.delete(user);
/// hibernateTemplate.getSessionFactory().close();
// }
// catch(HibernateException | DataAccessException ex)
// {
// throw ex;
// }*/
Criteria crit = createEntityCriteria();
crit.add(Restrictions.eq(“Id”, id));
ApplicationUser user = (ApplicationUser)crit.uniqueResult();
delete(user);
}

// @Override
// public void updateUser(int id)
// {

/* List users;
users = hibernateTemplate.getSessionFactory().openSession()
.createQuery(“from users where id=”+id)
.setParameter(0, id)
.list();
try
{
ApplicationUser user = users.get(id);
hibernateTemplate.update(user);
hibernateTemplate.getSessionFactory().close();
}
catch(HibernateException | DataAccessException ex)
{
throw ex;
}*/
// }

@Override
public ApplicationUser findUserById(int id)
{
ApplicationUser user = getByKey(id);
if(user!=null){
Hibernate.initialize(user.getUsername());
}
return user;
}
}

public interface UsersDAO {
public List findAllUsers();
public void addUser(ApplicationUser user);
// public void updateUser(int id);
public void deleteUser(int id);
public ApplicationUser findUserById(int id);
}
@Configuration
@EnableTransactionManagement
@ComponentScan({ “safecity.Configure” })
@PropertySource(value = { “classpath:application.properties” })
public class HibernateConfiguration {

@Autowired
private Environment environment;

@Bean
public LocalSessionFactoryBean sessionFactory() {
LocalSessionFactoryBean sessionFactory = new LocalSessionFactoryBean();
sessionFactory.setDataSource(dataSource());
sessionFactory.setPackagesToScan(new String[] { “safecity.safecityfull.Models” });
sessionFactory.setHibernateProperties(hibernateProperties());
return sessionFactory;
}

@Bean
public DataSource dataSource() {
DriverManagerDataSource dataSource = new DriverManagerDataSource();
dataSource.setDriverClassName(environment.getRequiredProperty(“jdbc.driverClassName”));
dataSource.setUrl(environment.getRequiredProperty(“jdbc.url”));
dataSource.setUsername(environment.getRequiredProperty(“jdbc.username”));
dataSource.setPassword(environment.getRequiredProperty(“jdbc.password”));
return dataSource;
}

private Properties hibernateProperties() {
Properties properties = new Properties();
properties.put(“hibernate.dialect”, environment.getRequiredProperty(“hibernate.dialect”));
properties.put(“hibernate.show_sql”, environment.getRequiredProperty(“hibernate.show_sql”));
properties.put(“hibernate.format_sql”, environment.getRequiredProperty(“hibernate.format_sql”));
return properties;
}

@Bean
@Autowired
public HibernateTransactionManager transactionManager(SessionFactory s) {
HibernateTransactionManager txManager = new HibernateTransactionManager();
txManager.setSessionFactory(s);
return txManager;
}
}
FAIL – Deployed application at context path /safecity but context failed to start

Feelik
I’m correct error. Netbeans reinstall and tomcat. My the project earned.

Thank you very much for your answers and book.

Balaji Sambhale
Thank you sir, Its working fine Initially i had face so many problems at the time build and clean up the
project but I got eventually

Onkar
I’m not able to login into the application with the username “sam” and the password “abc125″. Also, there is no such class by the name of QuickPasswordEncodingGenerator in the source code download package.

Please pardon my lack of knowledge or misinterpretation of any of the things mentioned in this tutorial. Any help is appreciated. Thanks.

websystique
Hi Omkar,Unless you have a bit different configuration than mentioned in this example, you should not get this error.Do you have any change in comparison to code from the downloadable?

Onkar
Thanks for the reply. Yes, it did work. I forgot to populate the ‘USER_PROFILE’ and JOIN table. Thank you so much for this tutorial.

Sorry to bother you again, but I do have one quick question though, if you will. I need to design a system where the client will get the registration page first and upon registration he/she will be redirected to the respective pages for “user/dba/admin” as per the role chosen at the time of registration. I assume, I would have to insert the respective records into the database through code. Not to mention, the initial record ‘sam’ will also be inserted through the code as well. Could you please tell me the workflow for this process and how should I approach this problem. Appreciate any help. Cheers.

websystique
What you are looking for is already well described in Spring Security 4 Role Based Login Example and Spring Security 4 Hibernate Role Based Login Example.

Pingback: Spring 4 MVC + JMS + ActiveMQ annotation based Example - WebSystique()

Ramesh K
Thanks for the Article.
I need this type of Example without UI, means only webservices. WIll you help regarding this please

websystique
Hi Ramesh, If you just have web-services i would rather recommend Spring Rest Basic Authentication or even better Spring OAuth2.

Cristian IC
Thank you. Excellent tutorial. I have everything working very well.
Now what I want to do is that a user at the time of registration is made an auto login. And how to do so that a logged-in user can do actions (for example, make a purchase of something) how he could get the user’s login (something like the username already done) and perform the transaction with the identifier Of current user.

Himanshu
Hello,

Again thanks for great tutorial,
I did followed this tutorial and tried to create one sample application similar to this so that I can practice more.
I and facing a problem with the sample application works fine for login and list of users, but while register a new user I am getting exception pring on UI just below the user profiles, the exception is

“Failed to convert property value of type to required type for property userRoles; nested exception is org.springframework.core.convert.ConversionFailedException: Failed to convert from type to type [@org.hibernate.validator.constraints.NotEmpty @javax.persistence.ManyToMany @javax.persistence.JoinTable com.himanshu.blogger.model.Role] for value 2; nested exception is java.lang.StackOverflowError”

I tried to find the problem for long time but it is not resolved.
If possible please help me, I can send you the complete code or specific files that you may need for analysis of the problem.

Thanks.

websystique
Hey Himanshu, I think the main issue you are facing is related to ‘missing’ converter in your example. Could you please make sure that a converter [like 'RoleToUserProfileConverter'] is registered in AppConfig?

Rafael Espí Botella
You can create a default constructor for your AbstractDao and thus you will not need to create this default constructor in each dao to set the clazz

@SuppressWarnings(“unchecked”)
public AbstractDAO() {
super();
clazz = ((Class) ((ParameterizedType) getClass().getGenericSuperclass()).getActualTypeArguments()[1]);
}

websystique
Thanks for a nice insight Rafael.

Razvan
It is spectacular how complicated can be something meant to be simple. Imagine you will need to add two factor authentication, challenge code, captcha or display some security image once the user name has been introduced. I’m not a security expert, but I’m sure a “regular programmer” having to implement all this, will surely introduce plenty of bugs and security flaws. To the end, the infamous line below will be preferred:

“select * from user u where u.name=’”+name+”‘ and md5(password)=’”+md5+”‘;”

Websystique made everything right according to Spring “dogma”; the issue lays in Spring itself. If Spring wants users, they need to consider making things simpler. As simple as they need to be. Start with this: why do you need so many classes around the same user concept? Why don’t you handle everything in one class, called User (cut Dao, Service, Interface, impl, etc.) Hibernate doesn’t require all this OO eye-candy. We may have to store tomorrow an user attribute of how many bananas the user ate (and one shouldn’t authenticate if ate too many bananas, let’s say 7), and we will have to change at least 10 classes. Plus it is not obvious where the sequence user.getBananas() >= 7 will go, or how many times the programmer will have to write it. The obsession for decoupling concepts translates into replicated crap, which is way worse than coupled code.

Since a while I have the idea of a manifesto called “Simplicity driven programming”, it is unfortunate that I have to surface it with a negative example.

Siavonen
I’ve tried to run this with some edits that I made in it and it’s giving me this error message, what is possibly wrong with it and how can I fix it?

These are the errors that I think that are the main cause

Caused by: org.springframework.beans.factory.NoSuchBeanDefinitionException: No qualifying bean found for dependency [fi.paino.painohallinta.converter.RoleToUserProfileConverter]: expected at least 1 bean which qualifies as autowire candidate. Dependency annotations: {@org.springframework.beans.factory.annotation.Autowired(required=true)}

org.springframework.beans.factory.UnsatisfiedDependencyException: Error creating bean with name ‘appConfig’: Unsatisfied dependency expressed through field ‘roleToUserProfileConverter’; nested exception is org.springframework.beans.factory.NoSuchBeanDefinitionException: No qualifying bean found for dependency [fi.paino.painohallinta.converter.RoleToUserProfileConverter]: expected at least 1 bean which qualifies as autowire candidate. Dependency annotations: {@org.springframework.beans.factory.annotation.Autowired(required=true)}

websystique
Hi, Please make sure that your package of your converter RoleToUserProfileConverter package is covered by @ComponentScan path.

Siavonen
can you email me your skype or some other type of messenger that you use? I have no idea how to fix it my self. I’ve tried to make it work in so many different ways that I’m all out of ideas. :D

Munarso
Make sure you have imported correct springframework.
https://uploads.disquscdn.com/images/b88f347e53be1e289d82676fcfea5a283339d8d6f4f4cbfe30f98c56e5641f71.png

Akhil B S
I have deployed this app in tomcat. But it shows sratus 404 error. is the database tables automatically created or do we need to create it?

websystique
You should create the table, they are not created automatically..

Ravi
Hi websystique, when i am deploy jar in webapp folder of tomcat it run perfectly but when running project in eclipse it dosen’t run following error occurred in browser

type Status report
message /SpringMVCHibernateWithSpringSecurityExample/
description The requested resource is not available.

Ravi
Hi Websystique, i want to get Json response from rest client, how i will get it
which parameters we have to pass from body or headers
and can you please tell me which type authentication used here token based or basic

Christopher
Hi Websystique, great example. If I wanted to only show the details of the logged in user on the ‘list’ page, if the user wasn’t an ‘ADMIN, but showed everything for the ‘ADMIN’. How would I do that?

Thanks,

websystique
Hi Christopher, Look at the security tags shown in above jsp, there you can use hasRole(‘ADMIN’) in order to show/hide the details based on your requirement.

Christopher
Ok, but what if i wanted a separate jsp page for the ‘admin’ and ‘user’ which would show after login depending on the type of user logged in, how would i go about that in the controller? Thanks.

Komal
Hi Webstique, I tried the code, it runs well, setup the database …but when I tried to create a user with existing ssid, I was expecting to get an error like the one you described in the messageSource, but I instead ge a null point exception

2016-09-03T12:41:30.620-0700|Warning: Servlet.service() for servlet jsp threw exception
java.lang.NullPointerException
at org.apache.jsp.WEB_002dINF.views.registration_jsp._jspx_meth_c_when_0(registration_jsp.java:561)
at org.apache.jsp.WEB_002dINF.views.registration_jsp._jspService(registration_jsp.java:213)
at org.apache.jasper.runtime.HttpJspBase.service(HttpJspBase.java:111)
at javax.servlet.http.HttpServlet.service(HttpServlet.java:790)

any idea?

websystique
Hi Komal, it seems conflicting versions of servlet & jsp libraries. Could you please try to comment out the dependencies for servlet-api.jar and jsp-api.jar or at least put them as provided and try again? Probably your server version already have a different version of these libraries.

Ravi
Hello, i have to get Json responce from rest client, how i will get it
which parameters we have to pass from body or headers

Ramon Grero
I am very new to Spring Security and tried out this tutorial code. It loads up quite nicely, but whenever I try to save a new user or edit an existing user, I get the following error:

HTTP Status 500 – Request processing failed; nested exception is
javax.validation.ValidationException: HV000041: Call to
TraversableResolver.isReachable() threw an exception.

Is there anything I can do?

websystique
Hi, Are you including the proper HashCode and equal methods in your entities [User,UserProfile] as shown in this tutorial?

Ramon Grero
Yes, the code is unchanged, I just wanted to see how it works before I started tinkering on it.

Ben
http://localhost:8080/login

HTTP Status 500 – Request processing failed; nested exception is org.springframework.transaction.CannotCreateTransactionException: Could not open Hibernate Session for transaction; nested exception is java.lang.NoClassDefFoundError: org/hibernate/engine/transaction/spi/TransactionContext

any ideas ;)?

jk
Could not open Hibernate Session for transaction. Watch up your SQLserver is up? Its basic

websystique
Are you using Hibernate 5?

jk
Hi Websystique! You have done great job! Its very usefull tuts. Have question about encoding charater sets. How can change encoding? I know that exists more than one method one of that is using filter chain

websystique
Hi jk, For encoding you may want to add CharacterEncodingFilter in your AppInitializer class. On view level,if you are using Spring form tags, acceptCharset can be used to specifying the encoding of input data understood by server.

jk
Have connect this filter Overloading onStartup method, but how it could be done on this example? At class AppInitializer i must add ServletConfig class, where i must reload onStartup method? Can you show example please?

websystique
public class AppInitializer extends AbstractAnnotationConfigDispatcherServletInitializer {

@Override
protected Class[] getRootConfigClasses() {
return new Class[] { AppConfig.class };
}

@Override
protected Class[] getServletConfigClasses() {
return null;
}

@Override
protected String[] getServletMappings() {
return new String[] { “/” };
}

@Override
protected Filter[] getServletFilters() {

CharacterEncodingFilter f = new CharacterEncodingFilter();
f.setEncoding(“UTF-8″);
f.setForceEncoding(true);

Filter [] filters = { f};
return filters;
}

}

Jack·Tong
very very perfect , lerarning… , thanks

Farooq Shaikh
Kindly provide jar files

Raj
Hi websystique Team,

when i am integrated Rest service on this example :
http://websystique.com/springmvc/spring-mvc-4-and-spring-security-4-integration-example/

then block all request GET, PUT,DELETE,POST

org.springframework.web.servlet.PageNotFound handleHttpRequestMethodNotSupported
WARNING: Request method ‘GET’ not supported

org.springframework.web.servlet.PageNotFound handleHttpRequestMethodNotSupported
WARNING: Request method ‘PUT’ not supported

org.springframework.web.servlet.PageNotFound handleHttpRequestMethodNotSupported
WARNING: Request method ‘DELETE’ not supported

org.springframework.web.servlet.PageNotFound handleHttpRequestMethodNotSupported
WARNING: Request method ‘POST’ not supported

already post this issue but nobody reply on this post ……..Plz give solution

Yura Halych
Hi, Raj. Did you solve this problem? I have the same and don`t know how to work around it.

svgkraju
Thanks for this posing. Really helpful. I was trying setup Junit in the same example. I copied HibernateConfiguration to com.websystique.springmvc.test.configuration and modified the line

@ComponentScan({ ” com.websystique.springmvc.test.configuration”, “com.websystique.springmvc.model”, “com.websystique.springmvc.service”, “com.websystique.springmvc.dao”, “com.websystique.springmvc.converter” })

My junit test has the following annotations:

import com.websystique.springmvc.test.configuration;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = HibernateConfiguration.class)
@Transactional
@Rollback

When I executed “Maven test” I am getting the following exception:

Exception in short: Could not autowire field: private org.springframework.security.crypto.password.PasswordEncoder

Full exception:

SEVERE: Caught exception while allowing TestExecutionListener [org.springframework.test.context.support.DependencyInjectionTestExecutionListener@4501b7af] to prepare test instance [com.rsa.projects.webtools.sfsms.test.LoginTest@4bb003e9]
java.lang.IllegalStateException: Failed to load ApplicationContext
at org.springframework.test.context.cache.DefaultCacheAwareContextLoaderDelegate.loadContext(DefaultCacheAwareContextLoaderDelegate.java:124)
at org.springframework.test.context.support.DefaultTestContext.getApplicationContext(DefaultTestContext.java:83)
at org.springframework.test.context.support.DependencyInjectionTestExecutionListener.injectDependencies(DependencyInjectionTestExecutionListener.java:117)
at org.springframework.test.context.support.DependencyInjectionTestExecutionListener.prepareTestInstance(DependencyInjectionTestExecutionListener.java:83)
at org.springframework.test.context.TestContextManager.prepareTestInstance(TestContextManager.java:228)
at org.springframework.test.context.junit4.SpringJUnit4ClassRunner.createTest(SpringJUnit4ClassRunner.java:230)
at org.springframework.test.context.junit4.SpringJUnit4ClassRunner$1.runReflectiveCall(SpringJUnit4ClassRunner.java:289)
at org.junit.internal.runners.model.ReflectiveCallable.run(ReflectiveCallable.java:12)
at org.springframework.test.context.junit4.SpringJUnit4ClassRunner.methodBlock(SpringJUnit4ClassRunner.java:291)
at org.springframework.test.context.junit4.SpringJUnit4ClassRunner.runChild(SpringJUnit4ClassRunner.java:249)
at org.springframework.test.context.junit4.SpringJUnit4ClassRunner.runChild(SpringJUnit4ClassRunner.java:89)
at org.junit.runners.ParentRunner$3.run(ParentRunner.java:290)
at org.junit.runners.ParentRunner$1.schedule(ParentRunner.java:71)
at org.junit.runners.ParentRunner.runChildren(ParentRunner.java:288)
at org.junit.runners.ParentRunner.access$000(ParentRunner.java:58)
at org.junit.runners.ParentRunner$2.evaluate(ParentRunner.java:268)
at org.springframework.test.context.junit4.statements.RunBeforeTestClassCallbacks.evaluate(RunBeforeTestClassCallbacks.java:61)
at org.springframework.test.context.junit4.statements.RunAfterTestClassCallbacks.evaluate(RunAfterTestClassCallbacks.java:70)
at org.junit.runners.ParentRunner.run(ParentRunner.java:363)
at org.springframework.test.context.junit4.SpringJUnit4ClassRunner.run(SpringJUnit4ClassRunner.java:193)
at org.apache.maven.surefire.junit4.JUnit4Provider.execute(JUnit4Provider.java:252)
at org.apache.maven.surefire.junit4.JUnit4Provider.executeTestSet(JUnit4Provider.java:141)
at org.apache.maven.surefire.junit4.JUnit4Provider.invoke(JUnit4Provider.java:112)
at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
at java.lang.reflect.Method.invoke(Method.java:497)
at org.apache.maven.surefire.util.ReflectionUtils.invokeMethodWithArray(ReflectionUtils.java:189)
at org.apache.maven.surefire.booter.ProviderFactory$ProviderProxy.invoke(ProviderFactory.java:165)
at org.apache.maven.surefire.booter.ProviderFactory.invokeProvider(ProviderFactory.java:85)
at org.apache.maven.surefire.booter.ForkedBooter.runSuitesInProcess(ForkedBooter.java:115)
at org.apache.maven.surefire.booter.ForkedBooter.main(ForkedBooter.java:75)
Caused by: org.springframework.beans.factory.BeanCreationException: Error creating bean with name ‘userService’: Injection of autowired dependencies failed; nested exception is org.springframework.beans.factory.BeanCreationException: Could not autowire field: private org.springframework.security.crypto.password.PasswordEncoder com.rsa.projects.webtools.fsms.service.UserServiceImpl.passwordEncoder; nested exception is org.springframework.beans.factory.NoSuchBeanDefinitionException: No qualifying bean of type [org.springframework.security.crypto.password.PasswordEncoder] found for dependency: expected at least 1 bean which qualifies as autowire candidate for this dependency. Dependency annotations: {@org.springframework.beans.factory.annotation.Autowired(required=true)}
at org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor.postProcessPropertyValues(AutowiredAnnotationBeanPostProcessor.java:334)
at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.populateBean(AbstractAutowireCapableBeanFactory.java:1214)
at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.doCreateBean(AbstractAutowireCapableBeanFactory.java:543)
at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.createBean(AbstractAutowireCapableBeanFactory.java:482)
at org.springframework.beans.factory.support.AbstractBeanFactory$1.getObject(AbstractBeanFactory.java:306)
at org.springframework.beans.factory.support.DefaultSingletonBeanRegistry.getSingleton(DefaultSingletonBeanRegistry.java:230)
at org.springframework.beans.factory.support.AbstractBeanFactory.doGetBean(AbstractBeanFactory.java:302)
at org.springframework.beans.factory.support.AbstractBeanFactory.getBean(AbstractBeanFactory.java:197)
at org.springframework.beans.factory.support.DefaultListableBeanFactory.preInstantiateSingletons(DefaultListableBeanFactory.java:772)
at org.springframework.context.support.AbstractApplicationContext.finishBeanFactoryInitialization(AbstractApplicationContext.java:839)
at org.springframework.context.support.AbstractApplicationContext.refresh(AbstractApplicationContext.java:538)
at org.springframework.test.context.support.AbstractGenericContextLoader.loadContext(AbstractGenericContextLoader.java:125)
at org.springframework.test.context.support.AbstractGenericContextLoader.loadContext(AbstractGenericContextLoader.java:60)
at org.springframework.test.context.support.AbstractDelegatingSmartContextLoader.delegateLoading(AbstractDelegatingSmartContextLoader.java:109)
at org.springframework.test.context.support.AbstractDelegatingSmartContextLoader.loadContext(AbstractDelegatingSmartContextLoader.java:261)
at org.springframework.test.context.cache.DefaultCacheAwareContextLoaderDelegate.loadContextInternal(DefaultCacheAwareContextLoaderDelegate.java:98)
at org.springframework.test.context.cache.DefaultCacheAwareContextLoaderDelegate.loadContext(DefaultCacheAwareContextLoaderDelegate.java:116)
… 31 more
Caused by: org.springframework.beans.factory.BeanCreationException: Could not autowire field: private org.springframework.security.crypto.password.PasswordEncoder com.rsa.projects.webtools.fsms.service.UserServiceImpl.passwordEncoder; nested exception is org.springframework.beans.factory.NoSuchBeanDefinitionException: No qualifying bean of type [org.springframework.security.crypto.password.PasswordEncoder] found for dependency: expected at least 1 bean which qualifies as autowire candidate for this dependency. Dependency annotations: {@org.springframework.beans.factory.annotation.Autowired(required=true)}
at org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor$AutowiredFieldElement.inject(AutowiredAnnotationBeanPostProcessor.java:573)
at org.springframework.beans.factory.annotation.InjectionMetadata.inject(InjectionMetadata.java:88)
at org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor.postProcessPropertyValues(AutowiredAnnotationBeanPostProcessor.java:331)
… 47 more
Caused by: org.springframework.beans.factory.NoSuchBeanDefinitionException: No qualifying bean of type [org.springframework.security.crypto.password.PasswordEncoder] found for dependency: expected at least 1 bean which qualifies as autowire candidate for this dependency. Dependency annotations: {@org.springframework.beans.factory.annotation.Autowired(required=true)}
at org.springframework.beans.factory.support.DefaultListableBeanFactory.raiseNoSuchBeanDefinitionException(DefaultListableBeanFactory.java:1373)
at org.springframework.beans.factory.support.DefaultListableBeanFactory.doResolveDependency(DefaultListableBeanFactory.java:1119)
at org.springframework.beans.factory.support.DefaultListableBeanFactory.resolveDependency(DefaultListableBeanFactory.java:1014)
at org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor$AutowiredFieldElement.inject(AutowiredAnnotationBeanPostProcessor.java:545)
… 49 more

svgkraju
Got it running by modifying the component scan line to

@ComponentScan({ ” com.websystique.springmvc.test.configuration”, “com.websystique.springmvc.model”, “com.websystique.springmvc.service”, “com.websystique.springmvc.dao”, “com.websystique.springmvc.converter”, “com.websystique.springmvc.security” })

svgkraju
There must be a some simpler way than how I did it. Why duplicate code is needed to achieve this simple one line change? Any better idea?

Vincent Zheng
Hi websystique, thank you again for the great tutorial, but cannot give a tutorial for responsive design for this application? I try to figure out myself and seems like not working…

websystique
Hi Vincent, For the layout, i used a very simplistic one from Bootstrap, worked straightaway. I wonder why it does not work for you. For any CSS related issue, may i ask you to have a look at bootstrap containers?

Himanshu Bhandari
Hi websystique, Thanks for this great post. I am able to run it, now I wanted to create a form for userProfile and on submit of that form I want to create a new Role in the DB, on which I am failing, getting error #400, please help.
Also profile converter and RoleTypes.java, if you can add little description, that why we need that, would be a great help. After removing both the files I was able to add UserProfile (Role) from DB.

Thanks.

hichri ines
Hi , how can i change the redirection of the button log in , i wanna change it to another jsp page

Raj
I am integrated RestService in this example for phasing issue:

Jul 10, 2016 8:51:07 PM org.springframework.web.servlet.PageNotFound handleHttpRequestMethodNotSupported
WARNING: Request method ‘PUT’ not supported

Jul 10, 2016 8:51:07 PM org.springframework.web.servlet.PageNotFound handleHttpRequestMethodNotSupported
WARNING: Request method ‘POST’ not supported

Jul 10, 2016 8:51:07 PM org.springframework.web.servlet.PageNotFound handleHttpRequestMethodNotSupported
WARNING: Request method ‘DELETE’ not supported
? Can you give me some advice ?

websystique
Hi Raj, Does your REST controller includes the methods to handle requests of type PUT[update],POST[create],DELETE[delete]?

Raj
i am already implemented RestController in this method Check below my code

@RestController
public class HelloWorldRestController {

@Autowired
UserService userService; //Service which will do all data retrieval/manipulation work

//——————-Retrieve All Users——————————————————–

@RequestMapping(value = “/Employee/”, method = RequestMethod.GET)
public ResponseEntity<List> listAllUsers() {
List users = userService.findImpAllUsers();
if(users.isEmpty()){
return new ResponseEntity<List>(HttpStatus.NO_CONTENT);//You many decide to return HttpStatus.NOT_FOUND
}
return new ResponseEntity<List>(users, HttpStatus.OK);
}

//——————-Retrieve Single Employee——————————————————–

@RequestMapping(value = “/Employee/{id}”, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity getUser(@PathVariable(“id”) int id) {
System.out.println(“Fetching Employee with id ” + id);
Employee Employee = userService.findImpById(id);
if (Employee == null) {
System.out.println(“Employee with id ” + id + ” not found”);
return new ResponseEntity(HttpStatus.NOT_FOUND);
}
return new ResponseEntity(Employee, HttpStatus.OK);
}

//——————-Create a Employee——————————————————–

@RequestMapping(value = “/Employee/”, method = RequestMethod.POST)
public ResponseEntity createUser(@RequestBody Employee Employee, UriComponentsBuilder ucBuilder) {
System.out.println(“Creating Employee ” + Employee.getUsername());

if (userService.isUserExist(Employee)) {
System.out.println(“A Employee with name ” + Employee.getUsername() + ” already exist”);
return new ResponseEntity(HttpStatus.CONFLICT);
}

String age = String.valueOf(Employee.getAge());
Employee.setAge(Integer.parseInt(age));
userService.saveUser(Employee);

HttpHeaders headers = new HttpHeaders();
headers.setLocation(ucBuilder.path(“/Employee/{id}”).buildAndExpand(Employee.getId()).toUri());
return new ResponseEntity(headers, HttpStatus.CREATED);
}

//——————- Update a Employee ——————————————————–

@RequestMapping(value = “/Employee/{id}”, method = RequestMethod.PUT)
public ResponseEntity updateUser(@PathVariable(“id”) int id, @RequestBody Employee Employee) {
System.out.println(“Updating Employee ” + id);

Employee currentUser = userService.findImpById(id);

if (currentUser==null) {
System.out.println(“Employee with id ” + id + ” not found”);
return new ResponseEntity(HttpStatus.NOT_FOUND);
}

currentUser.setUsername(Employee.getUsername());
currentUser.setAddress(Employee.getAddress());
currentUser.setEmail(Employee.getEmail());
currentUser.setSalary(Employee.getSalary());
currentUser.setAge(Employee.getAge());
userService.updateUser(currentUser);
return new ResponseEntity(currentUser, HttpStatus.OK);
}

//——————- Delete a Employee ——————————————————–

@RequestMapping(value = “/Employee/{id}”, method = RequestMethod.DELETE)
public ResponseEntity deleteUser(@PathVariable(“id”) int id) {
System.out.println(“Fetching & Deleting Employee with id ” + id);
//
// Employee Employee = userService.findById(id);
// if (Employee == null) {
// System.out.println(“Unable to delete. Employee with id ” + id + ” not found”);
// return new ResponseEntity(HttpStatus.NOT_FOUND);
// }
//
userService.deleteUserById(id);
return new ResponseEntity(HttpStatus.NO_CONTENT);
}

//——————- Delete All Users ——————————————————–

@RequestMapping(value = “/Employee/”, method = RequestMethod.DELETE)
public ResponseEntity deleteAllUsers() {
System.out.println(“Deleting All Users”);

userService.deleteAllUsers();
return new ResponseEntity(HttpStatus.NO_CONTENT);
}

}

Raj
I awaiting for your reply but…nobody give solution for that
Plz give idea how integrate REST service with this aap….becoz i m facing

org.springframework.web.servlet.PageNotFound handleHttpRequestMethodNotSupported
WARNING: Request method ‘PUT’ not supported

websystique
Hello Raj, let me have a look if i can reproduce your issue.It seems simply a mapping issue. Did you alternatively try something like:

@RestController
@RequestMapping(“/Employee”)
public class HelloWorldRestController {

@RequestMapping(value = “/”, method = RequestMethod.DELETE)
public ResponseEntity deleteAllUsers() {…}
}

Raj
@RestController
@RequestMapping(“/groups”)
public class GroupController {

@Autowired
UserService userService;

@RequestMapping(value = “/createGroup/”, method = RequestMethod.POST)
public ResponseEntity createUser(@RequestBody GroupVo groupVo, UriComponentsBuilder ucBuilder) {
System.out.println(“Creating User ” + groupVo.getName());

if (groupVo==null) {
System.out.println(“A User with name ” + groupVo.getName() + ” already exist”);
return new ResponseEntity(HttpStatus.CONFLICT);
}
GroupEntity group = new GroupEntity();
group.setName(groupVo.getName());
UserEntity user = userService.findBySSO(groupVo.getEmail());
group.setOwnerId(user);
Set userEntities = new HashSet();
userEntities.add(user);
group.setGroupUsers(userEntities);
userService.saveOrUpdate(group);
HttpHeaders headers = new HttpHeaders(); headers.setLocation(ucBuilder.path(“/createGroup/{id}”).buildAndExpand(group.getId()).toUri());
return new ResponseEntity(headers, HttpStatus.CREATED);
}
}

This is my code : but facing issue

PM org.springframework.web.servlet.PageNotFound handleHttpRequestMethodNotSupported
WARNING: Request method ‘POST’ not supported

Plz give solution i m awaiting for your reply..
becoz all posibility try but i am not getting any solution

Raj
Hi ,

How i can allow

org.springframework.web.servlet.PageNotFound handleHttpRequestMethodNotSupported
WARNING: Request method ‘PUT’ not supported

Http request for rest service ……….

Mary
Hi! Amazing post friend !! I’s really helpful!! How complicated could it be to add a profile picture ? Can you give me some advice ?

Mary
Sorry @websystique:disqus, i just saw this post: http://websystique.com/springmvc/spring-mvc-4-fileupload-download-hibernate-example/
I guess I just have to integrate both projects. Tks anyway

Sergio Trujillo
You could make a tutorial of Spring Security + LDAP?

websystique
Hi Sergio, sounds interesting, let me have a look.

Sergio Trujillo
Thanks! :)

hichri ines
HI what should i do if i need to add a button at start page that redirects me to create user

websystique
Hi, unless misunderstood your question, it should be as simple as adding following on your page view[jsp]:
<a href=””>Add New User

hichri ines
soon i import the project i get a problem in pom.xml what should i do

websystique
Hi, Please try to do maven update after importing, should be fine.

hichri ines
i alredy done that. it says failure to transfer org.codehaus.plexus:plexus-io:pom:2.0.7 from https://repo.maven.apache.org/maven2 was cached in the local repository, resolution will not be reattempted until the update interval of central has elapsed or updates are forced. Original error: Could not transfer artifact org.codehaus.plexus:plexus-io:pom:2.0.7 from/to central (https://repo.maven.apache.org/maven2): The operation was cancelled

Mike
Hi, I created a project according to your tutorial. However, I getting
no bean named ‘springsecurityfilterchain’ is defined while I try to run the project.
Do you know what would be the reason?

websystique
Hi Mike,that’s strange. We do have a class which extends AbstractSecurityWebApplicationInitializer for this very setup. Are you still getting this error?

Mike
Hi, I found that the name of package I defined in App.config is wrong.
After correction its working now! Thanks so much!

Pingback: Spring Security 4 Hibernate Role Based Login Example - WebSystique()

Raza Khan
thank you websystique…

Mubasher
This is very informative article though I faced some problems, I have noticed that persistent_login table can contain multiple unique series for same username. I have produced this scenario by logging same user from two different browsers. Login was successful. however i faced
org.hibernate.NonUniqueResultException: query did not return a unique result: 2 ,

Record should be fetched based on series which is unique, But you are fetching based on username
crit.add(Restrictions.eq(“username”, username));
PersistentLogin persistentLogin = (PersistentLogin) crit.uniqueResult();

How can I resolve this problem?

websystique
Interesting. One possible solution could be :Make username key unique in persistent_logins table, and then in create method implementation of TokenRepository, check if there is already an entry with that token.username, if yes, do not insert a new entry at all for that user. You may even prefer to raise an alarm to the user saying that a user with same name is already logged in on a different browser/device etc.

Mubasher
Actually That is not our requirement. user can logged in from different browsers. We could make username key unique by combination of deviceId+username but i just overrides the persistent repository Service class and use series as key to identify the user. That solved my problem. Thanks for your feedback.

Bakiyalakshmi Chandrasekaran
Hi Excellent article…by the way where we need to configure the login page as the start page?

Bakiyalakshmi Chandrasekaran
have same issue please help

websystique
Hi,

In SecurityConfiguration we have defined the configuration within configure method where ['/','/list'] are accessible to any user with any of role [User/Admin/DBA]. When you access the home page ['/'] , it checkS the role, but since the user is not logged in, login page gets shown. You don’t need to configure the login page, it is already the case. If for any reason you want to explicitly do it, return ‘login’ from the @RequestMapping annotated method which is mapped to ‘/’ or simply redirect to login ['redirect:/login'] from that method. Hope it helps.

Bakiyalakshmi Chandrasekaran
Thanks. Fantastic. I am learning Spring MVC and your post were helping me lot.
Thanks once again.

marcez2
Thanks so much for this post, is great. Im learning and this web site was really helpful. Your work is awesome. Im a little worried because I cant put to work this example.

I receive the next error message in the log:

Caused by: java.lang.IllegalStateException: Duplicate Filter registration for ‘springSecurityFilterChain’. Check to ensure the Filter is only configured once.

can someone help me please?

Milos Zivkovic
In pom I change this

from 4.0.0 to
4.2.4.RELEASE

also I add
for ViewResolverRegistry

org.beangle.webmvc
beangle-webmvc-core_2.11
0.3.0

Maven update and test

Bakiyalakshmi Chandrasekaran
can you please tell me where the start page is defined in this project. bcos the application loads /login by default.

itkhmerdotnet
Hello websystique,

Do you have plan to create a tutorial spring-mvc-4-and-spring-security-4-integration-example+mongodb

websystique
Sounds interesting, may look into in near future.

Vincent Zheng
A nice tutorial, but I have one issue… since the page kind of like not responsive design, how can I fix the issue like the picture below? As you can see, some of the button are not visible unless you shrink the size of the page…

websystique
Hi Vincent, it is a CSS issue, i would recommend to use bootstrap containers to mange the content in a responsive fashion.

Vincent Zheng
can you show me how to do this? I try a lot but cant figure out the solution….

r4lly99
nice tutorial , can i combine this with angularjs http service in view ? can i create controller with response entity in return to get json format ?

websystique
Yes you can. For JSON response, have a look at this post.

FuSsA FyBy
Hi @websystique:disqus ,Thanks for tutorial
Creating Token for user is not working for me :/

websystique
Hi, what issue are you facing exactly?

FuSsA FyBy
When im login successfully the token is not created and not persisted in database..
But when i logout.. i got a message from logger that the token is deleted .. which mean that when i click on logout the method handling with deleting tokens is called.. but when i login the method handling creating and persisting it is not called..

websystique
Hi, Did you configure the tokenRepository as shown in SecurityConfiguration class? May i ask you to try to run this downloaded example as it is once before tweaking it based on your needs? I don’t see why it would not work. It is working in my environment.

uday
hello, i finally got jetty run to deploy the artifact but am getting the following error in intellij

Artifact SpringMVCHibernateWithSpringSecurityExample:war: Artifact is being deployed, please wait…
2016-05-18 00:28:24.419:WARN:oejw.WebAppContext:Scanner-1: Failed startup of context o.e.j.w.WebAppContext@31c5a539{/SpringMVCHibernateWithSpringSecurityExample,jar:file:///C:/Users/uday/Downloads/SpringMVCHibernateWithSpringSecurityExample/SpringMVCHibernateWithSpringSecurityExample/target/SpringMVCHibernateWithSpringSecurityExample.war!/,null}{C:UsersudayDownloadsSpringMVCHibernateWithSpringSecurityExampleSpringMVCHibernateWithSpringSecurityExampletargetSpringMVCHibernateWithSpringSecurityExample.war}
java.net.MalformedURLException: no !/ in spec
at java.net.URL.(URL.java:627)
at java.net.URL.(URL.java:490)
at java.net.URL.(URL.java:439)
at java.net.JarURLConnection.parseSpecs(JarURLConnection.java:175)

websystique
Hi Uday, is your jetty plugin configured with required java version?

uday
hi has anyone used intellij for this example. I am not able to figure out how to get the maven tomcat to be created. I am new to intellij.

Stradomski
Hi, thank you for good tutorial. I have a problem. IDEA write me exception “cannot find bean with qualifier” for userDetailsService in Security configuration and “No beans of ‘PersistentTokenRepository’ type found’ for tokenRepository. How i can fix this? Sorry for my bad english)

websystique
Hi Stradomski,

Please make sure that HibernateTokenRepositoryImpl is annotated with respective Spring annotation and the class could be scanned via component-scan:
@Repository(“tokenRepositoryDao”)
@Transactional
public class HibernateTokenRepositoryImpl …….{
}

Stradomski
I had a mistake: forgot to use component-scan in security configuration. All had worked after adding it. Thank you for answer.

Pingback: Spring Batch- Read an XML file and write to MySQL Database - WebSystique()

Arnish gupta
Hello, i learned a lot of things related spring,.
can you please provide spring boot tutorial ?

Hòa Khánh Nguyễn
Thanks for tutorial
Can we auto create/update database by hibernate here?

Najoua
Thank you for this amazing tutorial.
i have a question about it, How can I restrict choice of the roles ? I mean, I don’t want that every new registrated user choose ADMIN ? Can I for example show an other field to fill, if they choose ADMIN for example ( a code or something like that) ?

websystique
Hi Najoua,
Yes, you may prefer not to provide Admin option at all in drop-down but a separate field [say a checkbox]. You may also opt for not showing the role-list for anyone [even on update page]other than admin, then creating a separate field would not even be required.

Najoua
Thanks for answering me. But, I don’t really get what you said.
for example : for the registration form, I will only show two options in the drop-down list. And, if I want to define a user as admin, I may do it via the update on the admin dashboard. Is is that ?

websystique
Yes Indeed.

Najoua
How can I only show two roles for example in the drop down list? Can you please give me an idea

websystique
Hi Najoua,

You get the complete list from userProfileService , called in AppController.

@ModelAttribute(“roles”)
public List initializeProfiles() {
return userProfileService.findAll();
}

If you want to show only two roles, you can create a separate method in userProfileSerive say ‘findNonAdminRoles() and return only two from DB.

Cristian Ruiz
Hello! I tried to import that project into my workspace, I’m using spring tool suite as IDE. when import the project maven configuration problems popup. “Cannot change version of project facet Dynamic Web Module to 3.1″ Help please

Pandurang Nawale
awesome….

websystique
