using AutoMapper;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;

namespace IdentityServerPersistence.AutoMap;

internal class AttributeStringValueListConverter : ITypeConverter<ICollection<string>, IAttributeValueList<string>>
{
    public IAttributeValueList<string> Convert(ICollection<string> source, IAttributeValueList<string> destination, ResolutionContext context)
    {
        var list = new AttributeStringValueList(source.ToList());
        return list;
    }
}