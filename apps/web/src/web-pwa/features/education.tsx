import { ChevronDown } from "lucide-react";
const tips = [
  [
    "Um preço bom demais para ser verdade",
    "Compare o valor com outras lojas. Descontos muito fora do normal merecem uma segunda checagem, mesmo quando o site parece bem-feito.",
  ],
  [
    "PIX para alguém que você não conhece",
    "Confira o nome de quem vai receber antes de confirmar. Se for uma pessoa desconhecida e a loja não explicar a relação, não pague até esclarecer. Prefira uma opção com proteção ao comprador.",
  ],
  [
    "Um endereço quase igual ao de uma marca",
    "Uma letra trocada ou um hífen a mais pode mudar tudo. Encontre o endereço em um canal oficial da marca; não confie só no nome e no desenho da página.",
  ],
  [
    "Pressão para pagar agora",
    "Contadores e mensagens de urgência não devem decidir por você. Pare, confira a loja e peça uma segunda opinião antes de pagar.",
  ],
  [
    "Pouca informação sobre quem vende",
    "Procure identificação da empresa e um contato que funcione. A falta de dados na análise pode ser falha da fonte: confirme por outro canal, sem concluir que isso prova um golpe.",
  ],
  [
    "Links recebidos em mensagens",
    "Até uma pessoa conhecida pode encaminhar um link ruim sem perceber. Confira o endereço completo e evite informar senhas ou códigos recebidos por mensagem.",
  ],
  [
    "A experiência de outros compradores",
    "Leia relatos recentes em mais de uma fonte. Ausência de reclamações não garante confiança: a loja pode ser nova ou ter poucas informações públicas.",
  ],
];
export function Education() {
  return (
    <section className="education section-block" id="dicas">
      <div className="section-top">
        <div>
          <p className="eyebrow">UM CUIDADO A MAIS</p>
          <h2>Antes de fechar a compra</h2>
        </div>
        <p className="section-description">
          O link é só o começo.
          <br />
          Sua atenção também protege.
        </p>
      </div>
      <div className="tips-grid">
        {tips.map(([title, text], index) => (
          <details key={title}>
            <summary>
              <span className="step-number">0{index + 1}</span>
              <span>{title}</span>
              <ChevronDown size={16} />
            </summary>
            <p>{text}</p>
          </details>
        ))}
      </div>
    </section>
  );
}
