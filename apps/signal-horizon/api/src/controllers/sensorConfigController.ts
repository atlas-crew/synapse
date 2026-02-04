import { Request, Response } from 'express';
import { SensorConfigService } from '../services/sensorConfigService.js';
import { SensorConfigSchema } from '../schemas/sensorConfig.js';
import { ErrorCatalog, handleRouteError, handleValidationError } from '../lib/errors.js';
import { sendProblem } from '../lib/problem-details.js';

export class SensorConfigController {
  constructor(private service: SensorConfigService) {}

  async getConfig(req: Request, res: Response) {
    const { sensorId } = req.params;
    try {
      const config = await this.service.getConfig(sensorId);

      if (!config) {
        const entry = ErrorCatalog.NOT_FOUND;
        return sendProblem(res, entry.status, 'Configuration not found', {
          code: entry.code,
          hint: entry.hint,
          instance: req.originalUrl,
          context: { sensorId, operation: 'getConfig' },
        });
      }

      return res.json(config);
    } catch (error) {
      const log = (req as unknown as { log?: { error: (...args: unknown[]) => void } }).log;
      return handleRouteError(res, error, log ?? console, {
        instance: req.originalUrl,
        sensorId,
        operation: 'getConfig',
      });
    }
  }

  async updateConfig(req: Request, res: Response) {
    const { sensorId } = req.params;
    
    // Check authentication
    const tenantId = req.auth?.tenantId;
    if (!tenantId) {
      const entry = ErrorCatalog.UNAUTHORIZED;
      return sendProblem(res, entry.status, entry.message, {
        code: entry.code,
        hint: entry.hint,
        instance: req.originalUrl,
        context: { sensorId, operation: 'updateConfig' },
      });
    }

    // Validate request body
    const result = SensorConfigSchema.safeParse(req.body);
    if (!result.success) {
      return handleValidationError(res, result.error, {
        instance: req.originalUrl,
        context: { sensorId, operation: 'updateConfig' },
      });
    }

    try {
      const { version, commandId } = await this.service.updateConfig(
        req,
        sensorId,
        result.data,
        tenantId
      );
      return res.json({ 
        success: true, 
        version,
        commandId,
        message: commandId ? 'Configuration pushed to sensor' : 'Configuration saved (sensor offline)'
      });
    } catch (error) {
      const log = (req as unknown as { log?: { error: (...args: unknown[]) => void } }).log;
      return handleRouteError(res, error, log ?? console, {
        instance: req.originalUrl,
        sensorId,
        tenantId,
        operation: 'updateConfig',
      });
    }
  }
}
