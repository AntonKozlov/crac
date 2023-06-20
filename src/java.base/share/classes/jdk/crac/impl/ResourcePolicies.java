package jdk.crac.impl;

import jdk.internal.crac.LoggerContainer;
import sun.security.action.GetPropertyAction;

import java.io.*;
import java.util.HashMap;
import java.util.Properties;

public class ResourcePolicies {
    private static final String POLICIES_FILE_PROPERTY = "jdk.crac.resource-policies";
    private static final String POLICY_PREFIX = "policy.";

    private static abstract class Policy { }

    public static class FD extends Policy {
        public enum Action {
            THROW,
            IGNORE,
        }

        private final int id;
        private final Action action;

        private static final FD DEFAULT = new FD(-1, Action.THROW);

        private FD(int id, Action action) {
            this.id = id;
            this.action = action;
        }

        public int getId() { return id; }
        public Action getAction() { return action; }

        private static final HashMap<Integer, FD> policies = new HashMap<>();

        static void addPolicy(Properties props, int num) {
            int id = Integer.parseInt(props.getProperty(POLICY_PREFIX + num + ".id"));
            Action action = Action.valueOf(props.getProperty(POLICY_PREFIX + num + ".action"));
            FD newPolicy = new FD(id, action);

            FD oldPolicy = policies.put(id, newPolicy);
            if (oldPolicy != null) {
                throw new RuntimeException("policy defined");
            }

            LoggerContainer.debug("ResourcePolicies: FDPolicy id={0} action={1}", id, action);
        }

        public static FD getPolicy(int id, String nativeDescription) {
            // FIXME check nativeDescription
            return policies.getOrDefault(id, DEFAULT);
        }
    }

    static {
        String path = GetPropertyAction.privilegedGetProperty(POLICIES_FILE_PROPERTY);
        if (path != null) {
            File file = new File(path);
            if (file.exists()) {
                try {
                    Properties properties = new Properties();
                    FileInputStream fis = new FileInputStream(file);
                    BufferedInputStream bis = new BufferedInputStream(fis);
                    properties.load(bis);

                    int n = 1;
                    String entry;
                    while ((entry = properties.getProperty(POLICY_PREFIX + n)) != null) {
                        switch (entry) {
                            case "FD" : FD.addPolicy(properties, n);
                        }
                        ++n;
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }
}
