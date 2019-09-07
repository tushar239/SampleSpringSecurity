Spring Security:
----------------

Authentication From:
https://docs.spring.io/spring-security/site/docs/current/reference/html/

Authorization From:
https://docs.spring.io/spring-security/site/docs/current/reference/html/authorization.html

and
Spring In Action 4.0
and
https://spring.io/guides/topicals/spring-security-architecture/


DelegatingFilterProxy, FilterChainProxy (from Spring In Action 4.0)
----------------------------------------
DelegatingFilterProxy is a special servlet filter that, by itself, doesn’t do much. Instead, it delegates to an implementation of javax.servlet.Filter that’s registered as a <bean> in the Spring application context

If you like configuring servlets and filters in the traditional web.xml file, you can do that with the <filter> element, like this:
<filter>
    <filter-name>springSecurityFilterChain</filter-name>
    <filter-class>
        org.springframework.web.filter.DelegatingFilterProxy
    </filter-class>
</filter>

The most important thing here is that the <filter-name> be set to springSecurityFilterChain.


If you'd rather configure DelegatingFilterProxy in Java with a WebApplicationInitializer, then all you need to do is create a new class that extends AbstractSecurityWebApplicationInitializer:

import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;

public class SecurityWebInitializer extends AbstractSecurityWebApplicationInitializer {}

Whether you configure DelegatingFilterProxy in web.xml or by subclassing AbstractSecurityWebApplicationInitializer, it will intercept requests coming into the application and delegate them to a bean whose ID is springSecurityFilterChain.
As for the springSecurityFilterChain bean itself, it’s another special filter known as FilterChainProxy. It’s a single filter that chains together one or more addi- tional filters. Spring Security relies on several servlet filters to provide different security features


Let’s create the simplest possible securit configuration.

@Configuration
@EnableWebMvcSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
}

@EnableWebMvcSecurity annotation configures a Spring MVC argument resolver so that handler methods can receive the authenticated user’s principal (or username) via @AuthenticationPrincipal annotated parameters.




 ********************************* Authentication and Authorization *********************************
 ----------------------------------------------------------------------------------------------------

 principal can be a UserDetails object or a string. UserDetails is just more information about the user (principal)
 AuthenticationManager authenticates username and password and then returns fully populated Authentication object that has all information about the user(principal) including his/her authorities(roles)). Authentication object has list of GrantedAuthority.
 One of the GrantedAuthority implementation is SimpleGrantedAuthority. This allows any user-specified String to be converted into a GrantedAuthority
 You can create your custom AuthenticationManager, UserDetails etc

 This Authentication object is later read by AccessDecisionManager for making authorization decision.

Consider a typical web application’s authentication process:

	-	You visit the home page, and click on a link.
	-	A request goes to the server, and the server decides that you’ve asked for a protected resource.
	-	As you’re not presently authenticated, the server sends back a response indicating that you must authenticate. The response will either be an HTTP response code, or a redirect to a particular web page.
	-   Depending on the authentication mechanism, your browser will either redirect to the specific web page so that you can fill out the form, or the browser will somehow retrieve your identity (via a BASIC authentication dialogue box, a cookie, a X.509 certificate etc.).
	-	The browser will send back a response to the server. This will either be an HTTP POST containing the contents of the form that you filled out, or an HTTP header containing your authentication details.
	-	Next the server will decide whether or not the presented credentials are valid. If they’re valid, the next step will happen. If they’re invalid, usually your browser will be asked to try again (so you return to step two above).
	-	The original request that you made to cause the authentication process will be retried. Hopefully you’ve authenticated with sufficient granted authorities to access the protected resource. If you have sufficient access, the request will be successful. Otherwise, you’ll receive back an HTTP error code 403, which means "forbidden".

Spring Security is a chain of filters
    https://www.logicbig.com/tutorials/spring-framework/spring-security/spring-security-components-and-configuration.html

    As you know, DelegatingFilterProxy delegates filtering to FilterChainProxy and then FilterChainProxy delegates filtering to chain of Spring-Managed Filter beans.
        - WebAsyncManagerIntegrationFilter
        - SecurityContextPersistenceFilter
        - HeaderWriterFilter
        - CsrfFilter
        - LogoutFilter
        - UserNamePasswordAuthenticationFilter
        - DefaultLoginPageGeneratingFilter
        - BasicAuthenticationFilter
        - RequestCacheAwareFilter
        - SecurityContextHolderAwareRequestFilter
        - AnonymousAuthenticationFilter
        - SessionManagementFilter
        - ExceptionTranslationFilter
        - FilterSecurityInterceptor

    Every single request goes through these list of filters.

    Let's understand a few of these important filters.

        UserNamePasswordAuthenticationFilter:
            It collects username and password from login form and calls AuthenticationManager to authenticate the user.
            Then it puts Authenticated user object called 'Authentication' inside SecurityContextHolder "SecurityContextHolder.getContext().setAuthentication(authResult)". That can be used later for authorization. This Authentication object will have everything about user (name, password, roles etc.)
            AuthenticationManager uses ProviderManager and ProviderManager uses Collection of AuthenticationProviders that you configure. AuthenticationProvider uses UserDetailService to fetch user information from various sources (in-memory, jdbc, Cas etc.). They are described more in detail later in this document.

        BasicAuthenticationFilter
            If Request object has header 'Authorization = Basic <Base64 encoded username>:<Base64 encoded password>', then it decodes username and password using Base64 and does authentication similar to UserNamePasswordAuthenticationFilter.

        ExceptionTranslationFilter
            It simply calls next filter in a chain. If that filter throws AuthorizationException, then initiates Authentication using AuthenticationEntryPoint.
            AuthenticationEntryPoint is configured in your own WebSecurityConfigurer using 'configure(HttpSecurity)' inside httpSecurity object.
            Examples of these AuthenticationEntryPoint can be BasicAuthenticationEntryPoint.

        FilterSecurityInterceptor (extends AbstractSecurityInterceptor) ---- VERY IMPORTANT
            This is a last Filter in chain. It extends AbstractSecurityInterceptor, which is responsible for the AUTHORIZATION.
            FilterSecurityInterceptor uses url based authorization. Whatever urls and allowed roles are configured in your own WebSecurityConfigurer using 'configure(HttpSecurity)', those urls and allowed roles will be provided to this interceptor using FilterInvocationSecurityMetadataSource.
            This interceptor will check whether Authentication object is already there inside SecurityContextHolder or not.
            Authentication object could have been put using any of the above mentioned filters or your custom filter that could do custom things to create Authentication object e.g. in CDK company, if request has header REMOTE_USER, a custom filter simply creates Authentication object with isAuthenticated=true and puts it in SecurityContextHolder.
            If Authentication object is not present in SecurityContextHolder, then it authenticates the user using AuthenticationManager first and puts Authentication object with isAuthentication=true in SecurityContextHolder.
            Then it performs Authorization using AccessDecisionManager.

            code inside this interceptor:

            InterceptorStatusToken token = super.beforeInvocation(fi);

                                                  - checks whether Authentication object exists with isAuthenticated=true in SecurityContextHolder. If not, then do authenticationManager.authenticate(authentication).

                                                  - Collection<ConfigAttribute> attributes = this.obtainSecurityMetadataSource().getAttributes(object);
                                                    SecurityMetadataSource contains all the information that you have configured using your WebSecurityConfigurer's configure(HttpSecurity) method.
                                                    It contains all urls, related roles that can access them etc.
                                                    There are few types of ConfigAttribute. Basically it contains the security information that you have attached with urls(like Role).

                                                  - Perform Authorization before rest endpoint is called
                                                    try {
                                                        accessDecisionManager.decide(authenticated Authentication object, object that needs to be invoked, configAttributes);
                                                    } catch (AccessDeniedException accessDeniedException) {
                                                            publishEvent(new AuthorizationFailureEvent(object, attributes, authenticated, accessDeniedException));
                                                            throw accessDeniedException;
                                                    }

                                                    if(publish on successful authorization is set to true) {
                                                        publishEvent(new AuthorizedEvent(object, attributes, authenticated));
                                                    }

                                                  - Authentication runAs = this.runAsManager.buildRunAs(authenticated, object,attributes);
                                                    Replace current Authentication object in SecurityContextHolder with this new 'runAs' Authentication object.




            try {
				fi.getChain().doFilter(fi.getRequest(), fi.getResponse()); --- FilterSecurityInterceptor is the last filter in chain. So, no more filters are remained. So, rest endpoint will be called at this point.
			}
			finally {
				super.finallyInvocation(token);
			}

			super.afterInvocation(token, null);

                                                    - Perform Authorization after rest endpoint is called. You can configure this kind of authorization also.
                                                      If Authorization is successful, returned object can be manipulated by Collection<AfterInvocationProvider> called by AfterInvocationManager.
                                                    try {
                                                        returnedObject = afterInvocationManager.decide(token.getSecurityContext().getAuthentication(), token.getSecureObject(), token.getAttributes(), returnedObject);
                                                    }
                                                    catch (AccessDeniedException accessDeniedException) {
                                                        publishEvent(authorizationFailureEvent);
                                                        throw accessDeniedException;
                                                    }



        NOTE: MethodSecurityInterceptor is not a Filter. It is a standard AOP based interceptor.
              There is another implementation of AbstractSecurityInterceptor and that is MethodSecurityInterceptor. It is not a Filter.
              It is a AOP based (JDK Dynamic Proxy based) security interceptor. It creates a proxy around your Controller and intercepts the endpoints in it.
              Unlike to FilterSecurityInterceptor's url based pattern, it uses annotations of methods like @Secured, @PreAuthorize, @PostAuthorize, @RolesAllowed etc.
              Using these annotations, MethodSecurityMetadataSource is created and fed to MethodSecurityInterceptor.

              https://springbootdev.com/2017/08/30/difference-between-secured-rolesallowed-and-preauthorizepostauthorize/

        @EnableWebSecurity enables normal filter based spring security. You need your own WebSecurityConfigurer or you need to configure related spring beans as described later in this document.
        @EnableGlobalMethodSecurity enables Method level security.


                                        AbstractSecurityInterceptor
                                                |
                                                |   Uses    AuthenticationManager for Authenticating the user, if it is not already authenticated (SecurityContextHolder doesn't have Authentication(user/principal) object with isAuthenticated=true
                                                |           AccessDecisionManager for authorization.
                                                |
                    --------------------------------------------------------------
                    |                                                            |
            FilterSecurityInterceptor implements Filter              MethodSecurityInterceptor implements MethodInterceptor

        Why are they called interceptors?
            Interceptor normally means Around advice. Around advice has a capability can elect whether or not to proceed with a method invocation, whether or not to modify the response, and whether or not to throw an exception.
            Spring Security provides an around advice for method invocations (using MethodSecurityInterceptor) as well as web requests (using FilterSecurityInterceptor).

        To secure
            - rest endpoints of your app, use Spring Security's interceptors.
            - service layer methods, use standard Spring AOP or AspectJ
            - domain objects, use AspectJ

What is a "secure object" anyway?
    Spring Security uses the term to refer to any object that can have security (such as an authorization decision) applied to it.

What is SecurityMetadataSource?

        SecurityMetadataSource contains information about the configuration that you do in your WebSecurityConfigurer's configure(HttpSecurity) method.
        This information is used by FilterSecurityInterceptor or MethodSecurityInterceptor as described above in this document.


                                                        SecurityMetadataSource
                                                                |
                                -------------------------------------------------------------------------------------
                                |                                                                                   |
                    FilterInvocationSecurityMetadataSource                                                 MethodSecurityMetadataSource
                                |                                                                                   |
----------------------------------------------------------------                                          -------------------------------------------------------------------------------------------------------------------------------
|                                                              |                                          |                                             |                                           |                                   |
DefaultFilterInvocationSecurityMetadataSource  ExpressionBasedFilterInvocationSecurityMetadataSource     SecuredAnnotationSecurityMetadataSource      PrePostAnnotationSecurityMetadataSource    Jsr250MethodSecurityMetadataSource   ......


What is Configuration Attribute?

    They may be simple role names or have more complex meaning, depending on the how sophisticated the AccessDecisionManager implementation is.
    The AbstractSecurityInterceptor is configured with a SecurityMetadataSource which it uses to look up the attributes for a secure object either from HttpSecurity object or method level annotations as described above.

                                        ConfigAttribute
                                            |
    -----------------------------------------------------------------------------------------------------------------------------------------------------
    |                                               |                               |                                   |                               |
WebExpressionConfigAttribute                PreInvocationExpressionAttribute     PostInvocationExpressionAttribute   SecurityConfig                 Jsr250SecurityConfig
Used by                                     Used by                              Used by                             Used by                        Used by
FilterInvocationSecurityMetadataSource      MethodSecurityMetadataSource         MethodSecurityMetadataSource        MethodSecurityMetadataSource   MethodSecurityMetadataSource

What is Run-As?
    https://www.baeldung.com/spring-security-run-as-auth


AuthenticationManager, ProviderManager, AuthenticationProvider:

    AuthenticationManager authenticates username and password and then returns fully populated Authentication object.
    It is just an interface.
    It's concrete implementation is ProviderManager.
    This ProviderManager, rather than handling the authentication request itself, it delegates to a list of configured AuthenticationProviders, each of which is queried in turn to see if it can perform the authentication.

    AuthenticationProvider provides fully populated Authentication object. It calls UserDetailsService to retrieve user information and perform the authentication.

    <bean id="authenticationManager"
            class="org.springframework.security.authentication.ProviderManager">
        <constructor-arg>
            <list>
                <ref local="daoAuthenticationProvider"/>
                <ref local="anonymousAuthenticationProvider"/>
                <ref local="ldapAuthenticationProvider"/>
            </list>
        </constructor-arg>
    </bean>


    DaoAuthenticationProvider uses UserDetailsService to load user information.
    JaasAuthenticationProvider uses JAAS.
    CasAuthenticationProvider uses Cas.

    <bean id="daoAuthenticationProvider" class="org.springframework.security.authentication.dao.DaoAuthenticationProvider">
        <property name="userDetailsService" ref="inMemoryDaoImpl"/>
        <property name="passwordEncoder" ref="passwordEncoder"/>
    </bean>

    <user-service id="inMemoryDaoImpl">
        <!-- Password is prefixed with {noop} to indicate to DelegatingPasswordEncoder that
        NoOpPasswordEncoder should be used. This is not safe for production, but makes reading
        in samples easier. Normally passwords should be hashed using BCrypt -->

        <user name="jimi" password="{noop}jimispassword" authorities="ROLE_USER, ROLE_ADMIN" />
        <user name="bob" password="{noop}bobspassword" authorities="ROLE_USER" />
    </user-service>
    or
    <user-service id="inMemoryDaoImpl" properties="users.properties"/>
    The properties file should contain entries in the form

    username=password,grantedAuthority[,grantedAuthority][,enabled|disabled]

    For example

    jimi=jimispassword,ROLE_USER,ROLE_ADMIN,enabled
    bob=bobspassword,ROLE_USER,enabled


    UserDetailsService based on external database:

    <bean id="dataSource" class="org.springframework.jdbc.datasource.DriverManagerDataSource">
        <property name="driverClassName" value="org.hsqldb.jdbcDriver"/>
        <property name="url" value="jdbc:hsqldb:hsql://localhost:9001"/>
        <property name="username" value="sa"/>
        <property name="password" value=""/>
    </bean>

    <bean id="userDetailsService"
        class="org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl">
        <property name="dataSource" ref="dataSource"/>
    </bean>


AccessDecisionManager

    I already explained how AccessDecisionManager work above in this document.

                                                      AccessDecisionManager
                                                                |
                        -----------------------------------------------------------------------------
                        |                                       |                                   |
            AffirmativeBased                                ConsensusBased                  UnanimousBased

            Iterates through DecisionVoters
                                 |
-----------------------------------------------------------------------------------------------------------------------------------------
|                                                                                           |                      |                    |
RoleVoter                                                                           RoleHierarchyVoter          WebExpressionVoter    .....
extracts Authorities (GrantedAuthority) from Authentication object stored
in SecurityContextHolder and compares them with Role related ConfigAttribute


Storing the SecurityContext between requests:

    In a typical web application, a user logs in once and is subsequently identified by their session Id. The server caches the principal information for the duration session.
    In Spring Security, the responsibility for storing the SecurityContext between requests falls to the SecurityContextPersistenceFilter, which by default stores the context as an HttpSession attribute between HTTP requests. It restores the context to the SecurityContextHolder for each request and, crucially, clears the SecurityContextHolder when the request completes. You shouldn’t interact directly with the HttpSession for security purposes. There is simply no justification for doing so - always use the SecurityContextHolder instead.


@EnableWebMvcSecurity

	This annotation configures a Spring MVC argument resolver so that handler methods can receive the authenticated user’s principal (or username) via @AuthenticationPrincipal-annotated parameters.

WebSecurityConfigurer

        It has following methods

        configure(WebSecurity)	- Override to configure Spring Security’s filter chain.
        configure(HttpSecurity) - Override to configure how requests are secured by interceptors.
        configure(AuthenticationManagerBuilder) - Override to configure user-details services.

	public class MyWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			/*
			// This says all urls are secured. That means they all should be authenticated. And any authenticated user with any role can access these urls. If authentication fails, use form login and basic authentication.
			// This is same as
			// http.antMatchers("/**") ---- authenticate all requests
			//     .authorizeRequests() --- authorize all authenticated users for all urls
			//     .antMatchers("/**")
			//     .authenticated()
			//	   .and()
			//	   .formLogin()
			//	   .and()
			//     .httpBasic();

			// As per https://spring.io/guides/topicals/spring-security-architecture/
			// each url pattern has its own filter chain.
			// So either you can configure the url patterns as shown below or add your own filter using http.addFilter(filter).
            // this filter can either url matching or any business logic like by looking at HttpRequest's header information, set Authentication(User) object inside SecurityContextHolder with isAuthenticated=true, so that that user acts like a pre-authenticated user and it won't be authenticated again.


			http
					.authorizeRequests()
					.antMatchers("/**")
					.authenticated()
					.and()// returns HttpSecurity object. formLogin() / httpBasic() are HttpSecurity'smethods
					.formLogin()
					.and()
					.httpBasic();

			*/
			// This says that all urls are secured (like http.antMatchers("/**"))
			// That means all urls with pattern "**/rest/v1.0/*" should be authenticated.
			// When you use /rest/v1.0/search url, after authentication, user with authority=ROLE_SEARCH (same as role=SEARCH) should be able to access it.
			// When you use any other url (e.g. /rest/v1.0/create), after authentication, user with authority=ROLE_REST_ALL (same as role=REST_ALL) should be able to access it.
			// If authentication or authorization fails, user should be directed to login page and basic authentication.

			// IMPORTANT: correct order of authentication (matchers) is very important.
			// If you put .antMatchers("**/rest/v1.0/*").hasAnyRole("REST_ALL")
			// before
			// .antMatchers("**/rest/v1.0/search/*").hasAnyAuthority("ROLE_SEARCH")
			// then even search call will pas first matcher and user with REST_ALL role (not having SEARCH role) will be able to access the search url.

			http
					.authorizeRequests()
					.antMatchers("**/rest/v1.0/search/*") //--- instead of this kind of configuration, you can use @PreAuthorize('hasAnyAuthority("ROLE_SEARCH")) annotation on top of your 'search' endpoint.
					.hasAnyAuthority("ROLE_SEARCH")
					.antMatchers("**/rest/v1.0/*")
					.hasAnyRole("REST_ALL") // is same as .hasAnyAuthority("ROLE_REST_ALL")
					.and()// returns HttpSecurity object. formLogin() / httpBasic() are HttpSecurity'smethods
					.formLogin()
					.and()
					.httpBasic();
		}

		@Autowired
		private DataSource dataSource;// required for jdbcAuthentication

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// AuthenticationManager uses ProviderManager to authenticate a user. ProviderManager iterates through all AuthenticationProviders and authenticates the user against all of them.
			// Below code will configure different AuthenticationProviders, which will be injected in ProviderManager

			// This line configures DaoAuthenticationProvider with userDetailService as in-memory userDetailService.
			auth.inMemoryAuthentication()
					.withUser("user").password("password").roles("REST_ALL")
					.and();

			// This line configures DaoAuthenticationProvider with userDetailService as JdbcDaoImpl
			auth.jdbcAuthentication();

			//auth.ldapAuthentication();

		}

