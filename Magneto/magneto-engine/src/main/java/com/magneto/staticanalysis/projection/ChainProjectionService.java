package com.magneto.staticanalysis.projection;

import com.magneto.staticanalysis.MethodCallChain;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 链级投影入口（SPEC 3.3）：每条链只分析一次，结果缓存后供静态分析输出与 fuzz 阶段共用。
 * 缓存键为 MethodCallChain，其 equals/hashCode 基于方法签名序列。
 */
@Slf4j
public class ChainProjectionService {

    private final ProjectionAnalyzer analyzer;

    private final Map<MethodCallChain, ChainProjection> cache = new LinkedHashMap<>();

    public ChainProjectionService() {
        this(new ProjectionAnalyzer());
    }

    public ChainProjectionService(ProjectionAnalyzer analyzer) {
        this.analyzer = analyzer;
    }

    public List<ChainProjection> analyzeAll(List<MethodCallChain> chains) {
        List<ChainProjection> projections = new ArrayList<>();
        for (int i = 0; i < chains.size(); i++) {
            projections.add(analyze(chains.get(i), "chain-" + i));
        }
        return projections;
    }

    public ChainProjection analyze(MethodCallChain chain) {
        ChainProjection cached = cache.get(chain);
        if (cached != null) {
            return cached;
        }
        return analyze(chain, "chain-" + Integer.toHexString(chain.hashCode()));
    }

    public ChainProjection getCached(MethodCallChain chain) {
        return cache.get(chain);
    }

    private ChainProjection analyze(MethodCallChain chain, String chainId) {
        ChainProjection projection = new ChainProjection(chainId);
        for (StepProjection step : analyzer.analyzeChain(chain)) {
            projection.addStep(step);
        }
        cache.put(chain, projection);
        log.info("projection analysed: {} steps={} breakpoints={}",
                chainId, projection.getSteps().size(), projection.getBreakpointCount());
        return projection;
    }
}
