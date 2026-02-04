import { Router, Request, Response } from 'express';
import { AuthCoverageAggregator } from '../../services/auth-coverage-aggregator.js';
import { RiskLevel } from '../../schemas/auth-coverage.js';
import { requireScope } from '../middleware/auth.js';

export function createAuthCoverageRoutes(aggregator: AuthCoverageAggregator): Router {
  const router = Router();
  
  /**
   * GET /api/v1/auth-coverage
   * Get all endpoint stats with optional filtering
   */
  router.get('/', requireScope('auth-coverage:read'), (req: Request, res: Response) => {
    const { risk, sort, limit, tenant } = req.query;
    
    let stats = aggregator.getAllEndpointStats(tenant as string | undefined);
    
    // Filter by risk level
    if (risk && ['low', 'medium', 'high', 'unknown'].includes(risk as string)) {
      stats = stats.filter(s => s.riskLevel === risk);
    }
    
    // Sort
    const sortField = (sort as string) || 'risk';
    const riskOrder: Record<RiskLevel, number> = { high: 0, medium: 1, unknown: 2, low: 3 };
    
    stats.sort((a, b) => {
      switch (sortField) {
        case 'risk':
          return riskOrder[a.riskLevel] - riskOrder[b.riskLevel];
        case 'requests':
          return b.totalRequests - a.totalRequests;
        case 'denial_rate':
          return b.denialRate - a.denialRate;
        case 'endpoint':
          return a.endpoint.localeCompare(b.endpoint);
        default:
          return 0;
      }
    });
    
    // Limit
    if (limit) {
      const limitNum = parseInt(limit as string, 10);
      if (!isNaN(limitNum) && limitNum > 0) {
        stats = stats.slice(0, limitNum);
      }
    }
    
    res.json({
      endpoints: stats,
      total: stats.length,
    });
  });
  
  /**
   * GET /api/v1/auth-coverage/summary
   * Get coverage summary stats
   */
  router.get('/summary', requireScope('auth-coverage:read'), (req: Request, res: Response) => {
    const { tenant } = req.query;
    res.json(aggregator.getSummary(tenant as string | undefined));
  });
  
  /**
   * GET /api/v1/auth-coverage/gaps
   * Get endpoints with auth gaps (high/medium risk)
   */
  router.get('/gaps', requireScope('auth-coverage:read'), (req: Request, res: Response) => {
    const { tenant } = req.query;
    const gaps = aggregator.getAuthGaps(tenant as string | undefined);
    
    res.json({
      gaps,
      total: gaps.length,
      highRiskCount: gaps.filter(g => g.riskLevel === 'high').length,
      mediumRiskCount: gaps.filter(g => g.riskLevel === 'medium').length,
    });
  });
  
  /**
   * GET /api/v1/auth-coverage/endpoint/:endpoint
   * Get stats for a specific endpoint (URL encoded)
   */
  router.get('/endpoint/:endpoint', requireScope('auth-coverage:read'), (req: Request, res: Response) => {
    const { tenant } = req.query;
    const endpoint = decodeURIComponent(req.params.endpoint);
    const key = tenant ? `${tenant}:${endpoint}` : endpoint;
    const stats = aggregator.getEndpointStats(key);
    
    if (!stats) {
      return res.status(404).json({ error: 'Endpoint not found' });
    }
    
    res.json(stats);
  });
  
  /**
   * GET /api/v1/auth-coverage/export
   * Export coverage data for developer use
   */
  router.get('/export', requireScope('auth-coverage:read'), (req: Request, res: Response) => {
    const { format, tenant } = req.query;
    const gaps = aggregator.getAuthGaps(tenant as string | undefined);
    
    if (format === 'csv') {
      const csv = [
        'Endpoint,Method,Total Requests,Denial Rate,Auth Pattern,Risk Level',
        ...gaps.map(g =>
          `"${g.endpoint}",${g.method},${g.totalRequests},${(g.denialRate * 100).toFixed(2)}%,${g.authPattern},${g.riskLevel}`
        ),
      ].join('\n');
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="auth-coverage-gaps.csv"');
      return res.send(csv);
    }
    
    res.json({
      exportedAt: new Date().toISOString(),
      gaps,
    });
  });
  
  return router;
}
