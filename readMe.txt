Spring Security:
----------------

From:
https://docs.spring.io/spring-security/site/docs/current/reference/html/authorization.html
and
Spring In Action 4.0


// Spring Security provides an around advice for method invocations as well as web requests.

// AbstractSecurityInterceptor:
// It is an interceptor that is responsible for authentication and authorization.
// It has different implementation for different types of objects (things that you want to secure).
// To secure method invocation, it uses MethodSecurityInterceptor. To secure Filter Chain invocation, it uses FilterSecurityInterceptor.


// Spring Security doesn’t mind how you put the Authentication object inside the SecurityContextHolder. The only critical requirement is that the SecurityContextHolder contains an Authentication which has a principal(user) before the AbstractSecurityInterceptor needs to authorize a user operation.
// You can totally avoid authentication part by putting Authenticaiton object in SecurityContextHolder with isAuthenticated set to true.

/*
	ExceptionTranslationFilter:
	It is a Spring Security filter that has responsibility for detecting any Spring Security exceptions that are thrown.
	Such exceptions will generally be thrown by an AbstractSecurityInterceptor.
 */


/*

 Authentication:
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

Spring Security has distinct classes responsible for most of the steps described above.
The main participants (in the order that they are used) are the ExceptionTranslationFilter, an AuthenticationEntryPoint and an "authentication mechanism", which is responsible for calling the AuthenticationManager.
*/

/*
	AuthenticationEntryPoint:
	It is responsible for step three in the above list. As you can imagine, each web application will have a default authentication strategy

		BasicAuthenticationEntryPoint
		CasAuthenticationEntryPoint (Central Authentication System)
		LoginUrlAuthenticationEntryPoint (Form based authentication system)
*/

/*
	Storing the SecurityContext between requests:

	In a typical web application, a user logs in once and is subsequently identified by their session Id. The server caches the principal information for the duration session. In Spring Security, the responsibility for storing the SecurityContext between requests falls to the SecurityContextPersistenceFilter, which by default stores the context as an HttpSession attribute between HTTP requests. It restores the context to the SecurityContextHolder for each request and, crucially, clears the SecurityContextHolder when the request completes. You shouldn’t interact directly with the HttpSession for security purposes. There is simply no justification for doing so - always use the SecurityContextHolder instead.

*/

/*
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


*/

/*
	Authorization:

	AbstractSecurityInterceptor provides a consistent workflow for handling secure object requests, typically:

		- Look up the "configuration attributes" associated with the present request
		- Submitting the secure object, current Authentication and configuration attributes to the AccessDecisionManager for an authorization decision
		- Optionally change the Authentication under which the invocation takes place
		- Allow the secure object invocation to proceed (assuming access was granted)
		- Call the AfterInvocationManager if configured, once the invocation has returned. If the invocation raised an exception, the AfterInvocationManager will not be invoked.

	What is Configuration Attributes?
	They may be simple role names or have more complex meaning, depending on the how sophisticated the AccessDecisionManager implementation is.
	The AbstractSecurityInterceptor is configured with a SecurityMetadataSource which it uses to look up the attributes for a secure object.
	e.g. PrePostAnnotationSecurityMetadataSource --- it reads annotations like @PreFilter, @PostFilter, @PreAuthorize, @PostAuthorize and sets their values as List<ConfigAttribute>
*/


/*

	Spring 3.0 onwards

	@EnableWebSecurity vs @EnableGlobalMethodSecurity:

	- EnableWebSecurity will provide configuration via HttpSecurity providing the configuration you could find with <http></http> tag in xml configuration, it's allow you to configure your access based on urls patterns, the authentication endpoints, handlers etc...
	You need have a subclass of WebSecurityConfigurer or WebSecurityConfigurerAdapter.
	You can override "protected void configure(HttpSecurity http)" to define your url patterns.

	configure(WebSecurity)	- Override to configure Spring Security’s filter chain.
	configure(HttpSecurity) - Override to configure how requests are secured by interceptors.
	configure(AuthenticationManagerBuilder) - Override to configure user-details services.

	- EnableGlobalMethodSecurity provides AOP security on methods, some of annotation it will enable are PreAuthorize PostAuthorize also it has support for JSR-250.

	@EnableWebMvcSecurity

	This annotation configures a Spring MVC argument resolver so that handler methods can receive the authenticated user’s principal (or username) via @AuthenticationPrincipal-annotated parameters.



	public class MyWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			/*
			// This says all urls are secured. That means they all should be authenticated. And any authenticated user with any role can access these urls. If authentication fails, use form login and basic authentication.
			http
					.authorizeRequests()
					.antMatchers("/**")
					.authenticated()
					.and()// returns HttpSecurity object. formLogin() / httpBasic() are HttpSecurity'smethods
					.formLogin()
					.and()
					.httpBasic();

			*/
			// This says that all urls with pattern "**/rest/v1.0/*" (it includes search url also) are secured.
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
					.antMatchers("**/rest/v1.0/search/*")
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
 */