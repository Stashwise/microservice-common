"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class PaginationService {
    static getPaginationMeta(limit, page, totalDocs) {
        const totalPages = Math.ceil(totalDocs / limit);
        const prevPage = totalPages < page || page === 1 ? null : page - 1;
        const nextPage = totalPages <= page ? null : page + 1;
        return {
            totalDocs,
            limit,
            page,
            totalPages,
            prevPage,
            nextPage,
            hasPrevPage: Boolean(prevPage),
            hasNextPage: Boolean(nextPage)
        };
    }
    static async basicPagination(options) {
        const { filter, modelName: Model, ...rest } = options;
        return await Model.paginate(filter, rest);
    }
    static async newAggregationPaginator(options) {
        const { filter, pipeline, limit, page, modelName: Model } = options;
        const [totalDocs, docs] = await Promise.all([
            Model.countDocuments(filter),
            Model.aggregate(pipeline)
        ]);
        return { docs, ...this.getPaginationMeta(limit, page, totalDocs) };
    }
    static async legacyAggregationPaginator(options) {
        const { modelName: Model } = options;
        const aggregate = Model.aggregate(options.pipeline);
        return await Model.aggregatePaginate(aggregate, options);
    }
    static async paginationWithAggregate(options) {
        const paginateFn = options.useNew ? this.newAggregationPaginator : this.legacyAggregationPaginator;
        return paginateFn(options);
    }
    static async paginate(modelName, options) {
        options.limit = options.limit || 20;
        if (options.limit > 50)
            options.limit = 50;
        if (options.exportLimit > 0)
            options.limit = options.exportLimit;
        options.page = options.page || 1;
        options.lean = true;
        options.sort = options.sort || { createdAt: -1 };
        return options.pipeline
            ? this.paginationWithAggregate({ ...options, modelName })
            : this.basicPagination({ ...options, modelName });
    }
}
exports.default = PaginationService;
