///usr/bin/env jbang "$0" "$@" ; exit $?
//JAVA 21
//DEPS info.picocli:picocli:4.7.5
//DEPS io.pebbletemplates:pebble:3.2.2

/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */

import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.Callable;
import java.util.function.Consumer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

@Command(name = "GenerateCweDictionary")
public class GenerateCweDictionary implements Callable<Integer> {

    private static final String OUTPUT_TEMPLATE = """
            /*
             * This file is part of Dependency-Track.
             *
             * Licensed under the Apache License, Version 2.0 (the "License");
             * you may not use this file except in compliance with the License.
             * You may obtain a copy of the License at
             *
             *   http://www.apache.org/licenses/LICENSE-2.0
             *
             * Unless required by applicable law or agreed to in writing, software
             * distributed under the License is distributed on an "AS IS" BASIS,
             * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
             * See the License for the specific language governing permissions and
             * limitations under the License.
             *
             * SPDX-License-Identifier: Apache-2.0
             * Copyright (c) Steve Springett. All Rights Reserved.
             */
            package {{ packageName }};

            {% if jakarta -%}
            import jakarta.annotation.Generated;
            {% else -%}
            import javax.annotation.Generated;
            {% endif -%}
            import java.util.LinkedHashMap;
            import java.util.Map;

            @Generated(value = "From dictionary version {{ version | escape(strategy="json") }}")
            public final class CweDictionary {

                public static final Map<Integer, String> DICTIONARY = new LinkedHashMap<>();

                static {
                    {% for entry in definitions -%}
                    DICTIONARY.put({{ entry.key }}, "{{ entry.value | escape(strategy="json") }}");
                    {% endfor -%}

                }

                private CweDictionary() {
                }

            }
            """;

    private final PebbleEngine pebbleEngine = new PebbleEngine.Builder()
            .newLineTrimming(false)
            .autoEscaping(false)
            .build();

    @Option(
            names = {"-v", "--version"},
            paramLabel = "VERSION",
            description = "Version of the CWE dictionary",
            required = true
    )
    private String version;

    @Option(
            names = {"-p", "--package"},
            paramLabel = "PACKAGE",
            description = "Package of the generated class",
            required = true
    )
    private String packageName;

    @Option(
            names = {"-o", "--output"},
            paramLabel = "OUTPUT_PATH",
            description = "Path to write the output to, will write to STDOUT if not provided"
    )
    private File outputFile;

    @Option(
            names = {"--jakarta"},
            description = "Generate code compatible with Jakarta EE"
    )
    private boolean jakarta;


    public static void main(final String[] args) {
        final var commandLine = new CommandLine(new GenerateCweDictionary());
        System.exit(commandLine.execute(args));
    }

    @Override
    public Integer call() throws Exception {
        final byte[] dictionaryBytes = downloadDictionary();
        final Map<Integer, String> definitions = parseDictionary(dictionaryBytes);

        final PebbleTemplate template = pebbleEngine.getLiteralTemplate(OUTPUT_TEMPLATE);
        final Map<String, Object> templateContext = Map.ofEntries(
                Map.entry("definitions", definitions),
                Map.entry("packageName", packageName),
                Map.entry("version", version),
                Map.entry("jakarta", jakarta)
        );

        final var writer = new StringWriter();
        template.evaluate(writer, templateContext);

        if (outputFile == null) {
            System.out.println(writer);
            return 0;
        }

        try (final OutputStream outputStream = Files.newOutputStream(outputFile.toPath())) {
            outputStream.write(writer.toString().getBytes(StandardCharsets.UTF_8));
        }

        return 0;
    }

    private byte[] downloadDictionary() throws IOException {
        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://cwe.mitre.org/data/xml/cwec_v%s.xml.zip".formatted(version)))
                .GET()
                .build();

        final Path tempFile = Files.createTempFile(null, null);
        tempFile.toFile().deleteOnExit();

        try (final HttpClient httpClient = HttpClient.newHttpClient()) {
            final HttpResponse<Path> response = httpClient.send(request, BodyHandlers.ofFile(tempFile));
            if (response.statusCode() != 200) {
                throw new IllegalStateException("Expected response code 200, but got: %d".formatted(response.statusCode()));
            }
        } catch (InterruptedException e) {
            throw new IllegalStateException("Interrupted while waiting for response", e);
        }

        try (final var zipFile = new ZipFile(tempFile.toFile())) {
            final ZipEntry entry = zipFile.getEntry("cwec_v%s.xml".formatted(version));
            if (entry == null) {
                throw new IllegalStateException("Dictionary file not found in ZIP archive");
            }

            final InputStream entryStream = zipFile.getInputStream(entry);
            return entryStream.readAllBytes();
        }
    }

    private Map<Integer, String> parseDictionary(final byte[] dictionaryBytes) throws Exception {
        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        final DocumentBuilder builder = factory.newDocumentBuilder();

        final Document doc = builder.parse(new ByteArrayInputStream(dictionaryBytes));
        final XPathFactory xPathFactory = XPathFactory.newInstance();
        final XPath xPath = xPathFactory.newXPath();

        final XPathExpression expr1 = xPath.compile("/Weakness_Catalog/Categories/Category");
        final XPathExpression expr2 = xPath.compile("/Weakness_Catalog/Weaknesses/Weakness");
        final XPathExpression expr3 = xPath.compile("/Weakness_Catalog/Views/View");

        final var definitions = new TreeMap<Integer, String>();

        final Consumer<NodeList> nodeParser = nodeList -> {
            for (int i = 0; i < nodeList.getLength(); i++) {
                final Node node = nodeList.item(i);
                final NamedNodeMap attributes = node.getAttributes();
                final Integer id = Integer.valueOf(attributes.getNamedItem("ID").getNodeValue());
                final String desc = attributes.getNamedItem("Name").getNodeValue();
                definitions.put(id, desc);
            }
        };

        nodeParser.accept((NodeList) expr1.evaluate(doc, XPathConstants.NODESET));
        nodeParser.accept((NodeList) expr2.evaluate(doc, XPathConstants.NODESET));
        nodeParser.accept((NodeList) expr3.evaluate(doc, XPathConstants.NODESET));

        return definitions;
    }

}
