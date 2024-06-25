import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import com.sun.net.httpserver.*;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.sql.*;
import java.util.Date;

public class HttpServer {
    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static com.sun.net.httpserver.HttpServer server;

    public static void main(String[] args) throws Exception {
        server = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress(8080), 0);

        server.createContext("/login", new LoginHandler());

        HttpContext goodContext = server.createContext("/api/good", new GoodHandler());
        goodContext.setAuthenticator(new Auth());

        HttpContext goodIdContext = server.createContext("/api/good/", new GoodIdHandler());
        goodIdContext.setAuthenticator(new Auth());

        server.setExecutor(null);
        server.start();
    }

    public static void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            String query = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String[] params = query.split("&");
            String login = null;
            String password = null;
            for (String param : params) {
                String[] pair = param.split("=");
                if ("login".equals(pair[0])) {
                    login = pair[1];
                } else if ("password".equals(pair[0])) {
                    password = pair[1];
                }
            }

            if ("admin".equals(login) && "5f4dcc3b5aa765d61d8327deb882cf99".equals(password)) {
                String token = Jwts.builder()
                        .setSubject(login)
                        .setIssuedAt(new Date())
                        .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                        .signWith(SECRET_KEY)
                        .compact();

                String jsonResponse = "{\"token\": \"" + token + "\"}";
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, jsonResponse.length());
                OutputStream os = exchange.getResponseBody();
                os.write(jsonResponse.getBytes());
                os.close();
            } else {
                exchange.sendResponseHeaders(401, -1);
            }
        }
    }

    static class GoodHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("PUT".equalsIgnoreCase(exchange.getRequestMethod())) {
                handlePut(exchange);
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }

        private void handlePut(HttpExchange exchange) throws IOException {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Good good = parseGood(body);

            if (good == null || good.getPrice() < 0) {
                exchange.sendResponseHeaders(409, -1);
                return;
            }

            try (Connection conn = DatabaseManager.getConnection()) {
                String sql = "INSERT INTO goods (name, price) VALUES (?, ?)";
                try (PreparedStatement stmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
                    stmt.setString(1, good.getName());
                    stmt.setDouble(2, good.getPrice());
                    int affectedRows = stmt.executeUpdate();

                    if (affectedRows == 0) {
                        throw new SQLException("Creating good failed, no rows affected.");
                    }

                    try (ResultSet generatedKeys = stmt.getGeneratedKeys()) {
                        if (generatedKeys.next()) {
                            long id = generatedKeys.getLong(1);
                            good.setId(id);
                        } else {
                            throw new SQLException("Creating good failed, no ID obtained.");
                        }
                    }
                }
            } catch (SQLException e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1);
                return;
            }

            String response = "{\"id\": " + good.getId() + "}";
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(201, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    static class GoodIdHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().getPath();

            long id = Long.parseLong(path.substring("/api/good/".length()));

            if ("GET".equalsIgnoreCase(method)) {
                handleGet(exchange, id);
            } else if ("POST".equalsIgnoreCase(method)) {
                handlePost(exchange, id);
            } else if ("DELETE".equalsIgnoreCase(method)) {
                handleDelete(exchange, id);
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }

        private void handleGet(HttpExchange exchange, long id) throws IOException {
            Good good = null;
            try (Connection conn = DatabaseManager.getConnection()) {
                String sql = "SELECT * FROM goods WHERE id = ?";
                try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                    stmt.setLong(1, id);
                    try (ResultSet rs = stmt.executeQuery()) {
                        if (rs.next()) {
                            good = new Good();
                            good.setId(rs.getLong("id"));
                            good.setName(rs.getString("name"));
                            good.setPrice(rs.getDouble("price"));
                        }
                    }
                }
            } catch (SQLException e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1);
                return;
            }

            if (good == null) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }

            String response = String.format("{\"id\":%d,\"name\":\"%s\",\"price\":%.2f}", good.getId(), good.getName(), good.getPrice());
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }

        private void handlePost(HttpExchange exchange, long id) throws IOException {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Good newGoodData = parseGood(body);

            if (newGoodData == null || newGoodData.getPrice() < 0) {
                exchange.sendResponseHeaders(409, -1);
                return;
            }

            try (Connection conn = DatabaseManager.getConnection()) {
                String sql = "UPDATE goods SET name = ?, price = ? WHERE id = ?";
                try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                    stmt.setString(1, newGoodData.getName());
                    stmt.setDouble(2, newGoodData.getPrice());
                    stmt.setLong(3, id);
                    int affectedRows = stmt.executeUpdate();

                    if (affectedRows == 0) {
                        exchange.sendResponseHeaders(404, -1);
                        return;
                    }
                }
            } catch (SQLException e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1);
                return;
            }

            exchange.sendResponseHeaders(204, -1);
        }

        private void handleDelete(HttpExchange exchange, long id) throws IOException {
            try (Connection conn = DatabaseManager.getConnection()) {
                String sql = "DELETE FROM goods WHERE id = ?";
                try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                    stmt.setLong(1, id);
                    int affectedRows = stmt.executeUpdate();

                    if (affectedRows == 0) {
                        exchange.sendResponseHeaders(404, -1);
                        return;
                    }
                }
            } catch (SQLException e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1);
                return;
            }

            exchange.sendResponseHeaders(204, -1);
        }
    }

    static class Auth extends Authenticator {
        @Override
        public Result authenticate(HttpExchange exchange) {
            Headers headers = exchange.getRequestHeaders();
            String authorization = headers.getFirst("Authorization");

            if (authorization == null || !authorization.startsWith("Bearer ")) {
                return new Authenticator.Failure(401);
            }

            String token = authorization.substring(7);
            try {
                Jwts.parserBuilder()
                        .setSigningKey(SECRET_KEY)
                        .build()
                        .parseClaimsJws(token);
                return new Authenticator.Success(new HttpPrincipal("user", "realm"));
            } catch (JwtException e) {
                return new Authenticator.Failure(401);
            }
        }
    }

    static Good parseGood(String body) {
        try {
            return new ObjectMapper().readValue(body, Good.class);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}
